"""Android permission intelligence: protection-level classification.

The dataset covers the runtime (dangerous) permission groups and a set of
signature/system permissions. Standard ``android.permission.*`` entries that are
not otherwise classified default to ``NORMAL``; anything outside the framework
namespace is treated as a custom permission with ``UNKNOWN`` protection.
"""

from __future__ import annotations

from dataclasses import dataclass

NORMAL = "NORMAL"
DANGEROUS = "DANGEROUS"
SIGNATURE = "SIGNATURE"
SIGNATURE_OR_SYSTEM = "SIGNATURE_OR_SYSTEM"
UNKNOWN = "UNKNOWN"

# Runtime (dangerous) permissions grouped as defined by the Android platform.
_DANGEROUS_GROUPS: dict[str, tuple[str, ...]] = {
    "CALENDAR": ("READ_CALENDAR", "WRITE_CALENDAR"),
    "CALL_LOG": ("READ_CALL_LOG", "WRITE_CALL_LOG", "PROCESS_OUTGOING_CALLS"),
    "CAMERA": ("CAMERA",),
    "CONTACTS": ("READ_CONTACTS", "WRITE_CONTACTS", "GET_ACCOUNTS"),
    "LOCATION": (
        "ACCESS_FINE_LOCATION",
        "ACCESS_COARSE_LOCATION",
        "ACCESS_BACKGROUND_LOCATION",
    ),
    "MICROPHONE": ("RECORD_AUDIO",),
    "PHONE": (
        "READ_PHONE_STATE",
        "READ_PHONE_NUMBERS",
        "CALL_PHONE",
        "ANSWER_PHONE_CALLS",
        "ADD_VOICEMAIL",
        "USE_SIP",
        "ACCEPT_HANDOVER",
    ),
    "SENSORS": ("BODY_SENSORS", "BODY_SENSORS_BACKGROUND"),
    "SMS": (
        "SEND_SMS",
        "RECEIVE_SMS",
        "READ_SMS",
        "RECEIVE_WAP_PUSH",
        "RECEIVE_MMS",
    ),
    "STORAGE": (
        "READ_EXTERNAL_STORAGE",
        "WRITE_EXTERNAL_STORAGE",
        "ACCESS_MEDIA_LOCATION",
    ),
    "ACTIVITY_RECOGNITION": ("ACTIVITY_RECOGNITION",),
    "NEARBY_DEVICES": (
        "BLUETOOTH_SCAN",
        "BLUETOOTH_ADVERTISE",
        "BLUETOOTH_CONNECT",
        "NEARBY_WIFI_DEVICES",
        "UWB_RANGING",
    ),
    "NOTIFICATIONS": ("POST_NOTIFICATIONS",),
    "MEDIA": (
        "READ_MEDIA_IMAGES",
        "READ_MEDIA_VIDEO",
        "READ_MEDIA_AUDIO",
        "READ_MEDIA_VISUAL_USER_SELECTED",
    ),
}

_SIGNATURE = frozenset(
    {
        "INSTALL_PACKAGES",
        "DELETE_PACKAGES",
        "WRITE_SECURE_SETTINGS",
        "MOUNT_UNMOUNT_FILESYSTEMS",
        "READ_LOGS",
        "SET_TIME",
        "REBOOT",
        "MANAGE_DEVICE_ADMINS",
        "BIND_DEVICE_ADMIN",
        "BIND_ACCESSIBILITY_SERVICE",
        "BIND_NOTIFICATION_LISTENER_SERVICE",
        "CAPTURE_AUDIO_OUTPUT",
        "CONTROL_LOCATION_UPDATES",
        "FACTORY_TEST",
        "MANAGE_EXTERNAL_STORAGE",
        "MODIFY_PHONE_STATE",
    }
)

# Reverse index from short permission name -> group.
_DANGEROUS_LOOKUP: dict[str, str] = {
    name: group for group, names in _DANGEROUS_GROUPS.items() for name in names
}

_ANDROID_PREFIX = "android.permission."


@dataclass(frozen=True)
class PermissionInfo:
    name: str
    protection_level: str
    group: str | None
    is_dangerous: bool
    is_custom: bool


def _short_name(name: str) -> str | None:
    if name.startswith(_ANDROID_PREFIX):
        return name[len(_ANDROID_PREFIX):]
    return None


def classify_permission(name: str) -> PermissionInfo:
    short = _short_name(name)
    if short is None:
        # Custom / third-party permission: protection level is app-defined.
        return PermissionInfo(name, UNKNOWN, None, False, True)
    if short in _DANGEROUS_LOOKUP:
        return PermissionInfo(name, DANGEROUS, _DANGEROUS_LOOKUP[short], True, False)
    if short in _SIGNATURE:
        return PermissionInfo(name, SIGNATURE, None, False, False)
    return PermissionInfo(name, NORMAL, None, False, False)


def classify_permissions(names: list[str]) -> list[PermissionInfo]:
    return [classify_permission(name) for name in names]
