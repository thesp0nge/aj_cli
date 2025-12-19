import sqlite3
import os
import json
from datetime import datetime
from prompt_toolkit import PromptSession
from prompt_toolkit.completion import WordCompleter
from prompt_toolkit.styles import Style
from prompt_toolkit.history import FileHistory

from core.logic import calculate_cvss_score, map_cvss_to_severity, CVSS_INSTALLED

from core.database import (
    get_audit_details,
    get_findings_for_report,
    import_kb_entries,
    get_kb_entry,
    BUGZILLA_PREFIX,
    FINDING_BUGZILLA_PREFIX,
    DB_FILE,
)
from core.reporting import generate_markdown_report
from core.bugzilla_api import BugzillaClient

style = Style.from_dict(
    {
        "prompt": "#00aa00 bold",
        "audit": "#00ffff bold",
    }
)


class AuditCommandHandler:
    def __init__(self):
        self.conn = sqlite3.connect(DB_FILE)
        self.c = self.conn.cursor()
        self.active_audit_id = None
        self.active_bugzilla_id = None

        # Setup prompt session with history
        history_file = os.path.join(
            os.path.dirname(os.path.abspath(__file__)), ".aj_history"
        )
        self.session = PromptSession(history=FileHistory(history_file))
        self._load_active_audit()
        if not CVSS_INSTALLED:
            print("WARNING: 'cvss' library not found. Scoring will be disabled.")
        self.bz_client = BugzillaClient("NaYfpQfBXb1YYObiAc8DAV7sW9eUO12zcXj78qhJ")

    def _load_active_audit(self):
        self.c.execute("SELECT id, bugzilla_id FROM audits WHERE is_active = 1")
        result = self.c.fetchone()
        if result:
            self.active_audit_id, self.active_bugzilla_id = result

    def get_prompt_tokens(self):
        ctx = self.active_bugzilla_id if self.active_audit_id else "No Active Audit"
        return [("class:audit", f"({ctx})"), ("class:prompt", "> ")]

    def _get_kb_completer(self):
        """
        FETCHES CWE entries from KB to populate the autocomplete list.
        This is used by do_add.
        """
        self.c.execute("SELECT cwe_id, title FROM kb_entries ORDER BY cwe_id ASC")
        data = [f"CWE-{row[0]} ({row[1]})" for row in self.c.fetchall()]
        return WordCompleter(data, ignore_case=True)

    def do_help(self, _):
        """Displays available commands."""
        print("\nAvailable Commands:")
        print("  open <number>    - Open/Create an audit (e.g., open 123456)")
        print("  close            - Close the current audit context")
        print("  add              - Add a new finding to the active audit")
        print("  list [severity]  - List findings or audits (if no active audit)")
        print("  triage           - Show audit summary and average CVSS")
        print("  report [file]    - Generate the Markdown report")
        print("  import_kb <file> - Import CWE templates from JSON")
        print("  exit             - Exit the application\n")

    def do_open(self, arg):
        """
        open <number|text>
        Opens an audit by Bugzilla ID number or searches by project name.
        """
        if not arg:
            print("Error: Missing Bugzilla ID number or Project Name.")
            return

        # Close existing context if any
        if self.active_audit_id:
            self.do_close("")

        # Check if input is a numeric Bugzilla ID
        if arg.isdigit():
            bz_id = f"{BUGZILLA_PREFIX}{arg}"
            self.c.execute(
                "SELECT id, bugzilla_id, project_name FROM audits WHERE bugzilla_id = ?",
                (bz_id,),
            )
            audit = self.c.fetchone()
        else:
            # Search by project name (case-insensitive partial match)
            search_term = f"%{arg}%"
            self.c.execute(
                "SELECT id, bugzilla_id, project_name FROM audits WHERE project_name LIKE ?",
                (search_term,),
            )
            results = self.c.fetchall()

            if not results:
                print(f"No audit found matching title: '{arg}'")
                return
            elif len(results) > 1:
                print(f"\nMultiple audits found for '{arg}':")
                for r_id, r_bz, r_name in results:
                    print(f"  [{r_id}] {r_bz} - {r_name}")
                print("\nPlease use 'open <number>' with the specific Bugzilla ID.")
                return
            else:
                audit = results[0]

        # Process the result
        if audit:
            self.active_audit_id, self.active_bugzilla_id, project_name = audit
            print(f"Audit loaded: {project_name} ({self.active_bugzilla_id})")

            # Update active status in DB
            self.c.execute(
                "UPDATE audits SET is_active = 1 WHERE id = ?", (self.active_audit_id,)
            )
            self.conn.commit()
        else:
            # If digit was provided but not found, allow creation
            if arg.isdigit():
                bz_id = f"{BUGZILLA_PREFIX}{arg}"
                print(f"Audit {bz_id} not found. Let's create it.")
                project_name = self.session.prompt("Enter Project Name: ")
                self.c.execute(
                    "INSERT INTO audits (bugzilla_id, project_name, start_date, is_active) VALUES (?, ?, ?, 1)",
                    (bz_id, project_name, datetime.now().strftime("%Y-%m-%d")),
                )
                self.conn.commit()
                self.active_audit_id = self.c.lastrowid
                self.active_bugzilla_id = bz_id
                print(f"New audit created: {project_name}")
            else:
                print(f"Could not find or create audit with search term: {arg}")

    def do_close(self, _):
        """Resets the active audit context."""
        if not self.active_audit_id:
            print("No active audit to close.")
            return
        self.c.execute(
            "UPDATE audits SET is_active = 0 WHERE id = ?", (self.active_audit_id,)
        )
        self.conn.commit()
        print(f"Audit {self.active_bugzilla_id} closed.")
        self.active_audit_id = None
        self.active_bugzilla_id = None

    def do_add(self, _):
        """Adds a new finding with KB autocomplete and CVSS calculation."""
        if not self.active_audit_id:
            print("Error: Open an audit first.")
            return

        print("\n--- New Finding ---")

        # 1. CWE & Title (with Autocomplete)
        completer = self._get_kb_completer()
        cwe_input = self.session.prompt(
            "CWE ID (e.g. 79) or '0' for custom [Tab for KB]: ", completer=completer
        )

        cwe_id = 0
        kb_entry = None
        if "CWE-" in cwe_input.upper():
            cwe_id = int(cwe_input.split("(")[0].replace("CWE-", "").strip())
        else:
            cwe_id = int(cwe_input or 0)

        if cwe_id > 0:
            kb_entry = get_kb_entry(cwe_id)
            if kb_entry:
                title = kb_entry["title"]
                print(f"Using KB Title: {title}")
            else:
                title = self.session.prompt("CWE not in KB. Enter Title: ")
        else:
            title = self.session.prompt("Enter Title: ")

        # 2. Finding Bugzilla ID
        while True:
            bz_num = self.session.prompt(
                f"Finding BZ Number ({FINDING_BUGZILLA_PREFIX}): "
            )
            if bz_num.isdigit():
                f_bz_id = f"{FINDING_BUGZILLA_PREFIX}{bz_num}"
                break
            print("Invalid input. Numeric only.")

        # 3. CVSS & Severity
        vector = self.session.prompt("CVSS v4 Vector: ")
        score, err = calculate_cvss_score(vector)
        if err:
            print(f"Scoring Error: {err}")
            score = 0.0

        severity = map_cvss_to_severity(score)
        print(f"Score: {score} | Severity: {severity}")

        # 4. Notes (Multiline)
        print("Enter Notes/PoC (Meta+Enter or Esc then Enter to finish):")
        notes = self.session.prompt("> ", multiline=True)

        # 5. Save
        try:
            self.c.execute(
                "INSERT INTO findings (audit_fk, finding_bugzilla_id, title, severity, cvss_v4_vector, cvss_v4_score, notes, cwe_id) VALUES (?,?,?,?,?,?,?,?)",
                (
                    self.active_audit_id,
                    f_bz_id,
                    title,
                    severity,
                    vector,
                    score,
                    notes,
                    cwe_id if cwe_id > 0 else None,
                ),
            )
            self.conn.commit()
            print("Finding saved successfully.")
        except sqlite3.IntegrityError:
            print("Error: This Finding BZ ID already exists in the database.")

    def do_list(self, arg):
        """Lists findings for active audit or all audits if none active."""
        if not self.active_audit_id:
            print("\n--- Audit Journal ---")
            self.c.execute("SELECT bugzilla_id, project_name, is_active FROM audits")
            rows = self.c.fetchall()
            if not rows:
                print("No audits found.")
                return

            for bz, proj, active in rows:
                status = "[ACTIVE]" if active else ""
                # Use str() fallback to avoid NoneType formatting errors
                print(f"{str(bz or 'N/A'):<12} | {str(proj or 'Unknown'):<25} {status}")
            return

        # Context: Active Audit - List Findings
        severity_filter = arg.upper() if arg else None
        sql = "SELECT finding_bugzilla_id, title, severity, cvss_v4_score FROM findings WHERE audit_fk = ?"
        params = [self.active_audit_id]

        if severity_filter:
            sql += " AND severity = ?"
            params.append(severity_filter)

        sql += " ORDER BY cvss_v4_score DESC"
        self.c.execute(sql, params)
        rows = self.c.fetchall()

        print(f"\n--- Findings for {self.active_bugzilla_id} ---")
        if not rows:
            print("No findings recorded yet.")
            return

        print("Fetching status from Bugzilla...")
        bz_ids = [r[0] for r in rows if r[0]]
        bz_statuses = self.bz_client.get_multiple_status(bz_ids)

        for bz, title, sev, score in rows:
            clean_id = bz.replace(FINDING_BUGZILLA_PREFIX, "")
            info = bz_statuses.get(clean_id, {})

            # Formattazione dello stato (es: [NEW], [RESOLVED FIXED])
            st = info.get("status", "???")
            res = info.get("resolution", "")
            bz_status_str = f"[{st}{' ' + res if res else ''}]"

            # Colore basato sullo stato (opzionale se usi prompt_toolkit)
            score_val = f"{score:>4.1f}" if score is not None else " N/A"

            print(f"{bz:<12} | {bz_status_str:<18} | {sev:<8} ({score_val}) | {title}")

    def do_edit(self, arg):
        """
        edit <finding_id>
        Interactively edit an existing finding. Press Enter to keep current values.
        """
        if not self.active_audit_id:
            print("Error: Open an audit first.")
            return

        if not arg or not arg.isdigit():
            print("Error: Please provide a numeric finding ID (e.g., edit 1).")
            return

        finding_id = int(arg)

        # 1. Fetch existing finding data
        self.c.execute(
            """
            SELECT finding_bugzilla_id, title, severity, cvss_v4_vector, cvss_v4_score, notes, cwe_id 
            FROM findings 
            WHERE id = ? AND audit_fk = ?
        """,
            (finding_id, self.active_audit_id),
        )

        row = self.c.fetchone()
        if not row:
            print(f"Error: Finding ID {finding_id} not found in current audit.")
            return

        # Map row to meaningful variables
        old_bz, old_title, old_sev, old_vector, old_score, old_notes, old_cwe = row

        print(f"\n--- Editing Finding {finding_id} ---")
        print("(Leave blank to keep current value)")

        # 2. Edit Finding Bugzilla ID
        new_bz_num = self.session.prompt(f"BZ Number [{old_bz}]: ")
        if new_bz_num.strip():
            new_bz = f"{FINDING_BUGZILLA_PREFIX}{new_bz_num.strip()}"
        else:
            new_bz = old_bz

        # 3. Edit Title
        new_title = self.session.prompt(f"Title [{old_title}]: ")
        new_title = new_title.strip() if new_title.strip() else old_title

        # 4. Edit CVSS Vector and Recalculate Severity
        new_vector = self.session.prompt(f"CVSS v4 Vector [{old_vector}]: ")
        if new_vector.strip():
            new_vector = new_vector.strip()
            new_score, err = calculate_cvss_score(new_vector)
            if err:
                print(f"Scoring Error: {err}. Score reset to 0.0.")
                new_score = 0.0
            new_sev = map_cvss_to_severity(new_score)
        else:
            new_vector = old_vector
            new_score = old_score
            new_sev = old_sev

        # 5. Edit CWE ID
        new_cwe_input = self.session.prompt(f"CWE ID [{old_cwe}]: ")
        if new_cwe_input.strip():
            try:
                new_cwe = int(new_cwe_input.strip())
            except ValueError:
                print("Invalid CWE format. Keeping old value.")
                new_cwe = old_cwe
        else:
            new_cwe = old_cwe

        # 6. Edit Notes (Multiline)
        print("Edit Notes/PoC (Current notes shown below. Press Meta+Enter to finish):")
        print(f"Current: {old_notes[:50]}...")
        new_notes = self.session.prompt(
            "> ", default=str(old_notes or ""), multiline=True
        )

        # 7. Update Database
        try:
            self.c.execute(
                """
                UPDATE findings 
                SET finding_bugzilla_id = ?, title = ?, severity = ?, 
                    cvss_v4_vector = ?, cvss_v4_score = ?, notes = ?, cwe_id = ?
                WHERE id = ?
            """,
                (
                    new_bz,
                    new_title,
                    new_sev,
                    new_vector,
                    new_score,
                    new_notes,
                    new_cwe,
                    finding_id,
                ),
            )
            self.conn.commit()
            print(f"Finding {finding_id} updated successfully.")
        except sqlite3.IntegrityError:
            print("Error: Integrity violation (possible duplicate Bugzilla ID).")
        except Exception as e:
            print(f"Error during update: {e}")

    def do_triage(self, _):
        """Calculates audit metrics based on CVSS v4."""
        if not self.active_audit_id:
            print("Error: No active audit.")
            return

        self.c.execute(
            "SELECT AVG(cvss_v4_score) FROM findings WHERE audit_fk = ? AND cvss_v4_score > 0",
            (self.active_audit_id,),
        )
        avg = self.c.fetchone()[0] or 0.0
        label = map_cvss_to_severity(avg)

        print("\n--- Audit Triage Summary ---")
        print(f"Average CVSS v4 Score: {avg:.1f}")
        print(f"Overall Severity:      {label}")
        print("-" * 30)

    def do_report(self, arg):
        """Generates the Markdown report."""
        if not self.active_audit_id:
            print("Error: No active audit.")
            return

        details = get_audit_details(self.active_audit_id)
        findings = get_findings_for_report(self.active_audit_id)

        self.c.execute(
            "SELECT AVG(cvss_v4_score) FROM findings WHERE audit_fk = ? AND cvss_v4_score > 0",
            (self.active_audit_id,),
        )
        avg = round(self.c.fetchone()[0] or 0.0, 1)

        content = generate_markdown_report(
            details, findings, avg, map_cvss_to_severity(avg)
        )
        filename = arg if arg else f"Report_{self.active_bugzilla_id}.md"

        with open(filename, "w") as f:
            f.write(content)
        print(f"Report generated: {filename}")

    def do_import_kb(self, arg):
        """Imports KB entries from a JSON file."""
        if not arg or not os.path.exists(arg):
            print("Error: Provide a valid JSON file path.")
            return
        with open(arg, "r") as f:
            data = json.load(f)
            count = import_kb_entries(data)
            print(f"Imported {count} entries to Knowledge Base.")

    def do_exit(self, _):
        """Cleanly exits the shell."""
        if self.active_audit_id:
            self.c.execute(
                "UPDATE audits SET is_active = 0 WHERE id = ?", (self.active_audit_id,)
            )
            self.conn.commit()
        print("Goodbye!")
        return True

    def do_delete(self, arg):
        """
        delete <finding_id>
        Deletes a specific finding from the active audit.
        """
        if not self.active_audit_id:
            print("Error: Open an audit first.")
            return

        if not arg or not arg.isdigit():
            print("Error: Please provide a numeric finding ID (e.g., delete 1).")
            return

        finding_id = int(arg)

        # Verify existence and ownership
        self.c.execute(
            "SELECT title FROM findings WHERE id = ? AND audit_fk = ?",
            (finding_id, self.active_audit_id),
        )
        row = self.c.fetchone()

        if not row:
            print(f"Error: Finding ID {finding_id} not found in this audit.")
            return

        confirm = self.session.prompt(
            f"Are you sure you want to delete finding '{row[0]}'? (y/N): "
        )
        if confirm.lower() == "y":
            self.c.execute("DELETE FROM findings WHERE id = ?", (finding_id,))
            self.conn.commit()
            print(f"Finding {finding_id} deleted.")
        else:
            print("Deletion cancelled.")

    def do_delete_audit(self, arg):
        """
        delete_audit <bugzilla_id_number>
        DANGER: Deletes an entire audit and all its associated findings.
        """
        if not arg or not arg.isdigit():
            print(
                "Error: Provide the numeric Bugzilla ID (e.g., delete_audit 1249084)."
            )
            return

        bz_id = f"{BUGZILLA_PREFIX}{arg}"

        self.c.execute(
            "SELECT id, project_name FROM audits WHERE bugzilla_id = ?", (bz_id,)
        )
        audit = self.c.fetchone()

        if not audit:
            print(f"Error: Audit {bz_id} not found.")
            return

        audit_id, proj_name = audit
        print(
            f"!!! WARNING: You are about to delete audit '{proj_name}' and ALL its findings."
        )
        confirm = self.session.prompt(
            f"Type the project name to confirm ('{proj_name}'): "
        )

        if confirm == proj_name:
            # Delete findings first (foreign key constraint)
            self.c.execute("DELETE FROM findings WHERE audit_fk = ?", (audit_id,))
            self.c.execute("DELETE FROM audits WHERE id = ?", (audit_id,))
            self.conn.commit()

            # Reset context if we deleted the active audit
            if self.active_audit_id == audit_id:
                self.active_audit_id = None
                self.active_bugzilla_id = None

            print(f"Audit {bz_id} and all related data have been purged.")
        else:
            print("Confirmation failed. Deletion aborted.")

    def do_config(self, arg):
        from core.config import get_config, save_config

        config = get_config()

        key = self.session.prompt(
            "Bugzilla API Key: ", default=config.get("bugzilla_api_key", "")
        )
        config["bugzilla_api_key"] = key

        save_config(config)
        print("Configuration saved. Please restart the tool to apply changes.")

    def default(self, line):
        if line:
            print(f"Unknown command: {line}")
