"""The warning shown wherever a collection profile has not been run on a real device."""
from __future__ import annotations

from .profiles import Profile

TITLE = "UNVALIDATED COLLECTION PROFILE"


def unvalidated_notice(profile: Profile) -> str:
    """Multi-line warning for a profile with no recorded run on a real device."""
    return (
        f"!! {TITLE}: {profile.display} ({profile.name})\n"
        "!! No command in this profile has been run against a real device or a vendor\n"
        "!! virtual edition. Commands, prompts, pager handling and output formats were\n"
        "!! checked only against vendor documentation and synthetic replays. The guard\n"
        "!! keeps impact-free steps read-only, but a command may fail, behave differently\n"
        "!! on your release, or return output the parsers do not recognise - which the\n"
        "!! analyzer reports as 'not evaluated', never as clean.\n"
        "!! Try it on a lab or virtual edition first, review every step with 'plan',\n"
        "!! and keep the vendor's own procedure to hand. See docs/VERIFICATION.md.\n"
    )


def replay_note(profile: Profile) -> str:
    return (f"note: profile {profile.name} has not been validated on a real device; "
            "replay exercises the parsers, not the device.\n")
