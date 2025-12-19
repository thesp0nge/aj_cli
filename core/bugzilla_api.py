import bugzilla
from core.config import get_config


class BugzillaClient:
    def __init__(self, api_key=None):
        config = get_config()
        self.url = config.get("bugzilla_url", "https://bugzilla.suse.com")
        self.api_key = config.get("bugzilla_api_key")

        if not self.api_key:
            print("[!] Warning: Bugzilla API Key not found in ~/.aj_config")
            print("[!] Some bugs may be inaccessible.")
            self.bz = bugzilla.Bugzilla(self.url)
        else:
            self.bz = bugzilla.Bugzilla(self.url, api_key=self.api_key)

    def get_bug_status(self, bug_id):
        """Returns the status and resolution of a bug."""
        try:
            clean_id = str(bug_id).replace("bsc#", "").strip()
            bug = self.bz.getbug(clean_id)
            return {
                "status": bug.status,
                "resolution": bug.resolution,
                "summary": bug.summary,
                "is_open": bug.is_open,
            }
        except Exception as e:
            return {"error": str(e)}

    def get_multiple_status(self, bug_ids):
        """Fetches status for a list of bug IDs in a single call."""
        clean_ids = [str(bid).replace("bsc#", "").strip() for bid in bug_ids]
        try:
            bugs = self.bz.getbugs(clean_ids)
            return {
                str(bug.id): {
                    "status": bug.status,
                    "resolution": bug.resolution,
                    "is_open": bug.is_open,
                }
                for bug in bugs
            }
        except Exception:
            return {}
