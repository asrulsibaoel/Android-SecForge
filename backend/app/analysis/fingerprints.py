"""Curated Java library fingerprints (package prefix -> product identity).

Presence is detected by decompiled package namespaces; versions are NOT inferred
from the prefix (only from embedded metadata). Product/CPE identity is used for
CVE correlation. This is a conservative, extensible starter set.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Fingerprint:
    prefix: str
    ecosystem: str
    name: str
    product: str           # CVE product identity
    cpe: str | None = None
    group: str | None = None
    artifact: str | None = None
    first_party: bool = False  # androidx/kotlin/google — usually shipped, lower CVE priority


FINGERPRINTS: tuple[Fingerprint, ...] = (
    Fingerprint("okhttp3", "maven", "okhttp", "okhttp", "cpe:2.3:a:squareup:okhttp", "com.squareup.okhttp3", "okhttp"),
    Fingerprint("retrofit2", "maven", "retrofit", "retrofit", None, "com.squareup.retrofit2", "retrofit"),
    Fingerprint("com.squareup.moshi", "maven", "moshi", "moshi", None, "com.squareup.moshi", "moshi"),
    Fingerprint("com.squareup.picasso", "maven", "picasso", "picasso", None, "com.squareup.picasso", "picasso"),
    Fingerprint("com.google.gson", "maven", "gson", "gson", "cpe:2.3:a:google:gson", "com.google.code.gson", "gson"),
    Fingerprint("com.bumptech.glide", "maven", "glide", "glide", None, "com.github.bumptech.glide", "glide"),
    Fingerprint("org.bouncycastle", "maven", "bouncycastle", "bouncy_castle", "cpe:2.3:a:bouncycastle:bc-java", "org.bouncycastle", "bcprov"),
    Fingerprint("io.reactivex", "maven", "rxjava", "rxjava", None, "io.reactivex.rxjava2", "rxjava"),
    Fingerprint("org.jsoup", "maven", "jsoup", "jsoup", "cpe:2.3:a:jsoup:jsoup", "org.jsoup", "jsoup"),
    Fingerprint("com.fasterxml.jackson", "maven", "jackson", "jackson-databind", "cpe:2.3:a:fasterxml:jackson-databind", "com.fasterxml.jackson.core", "jackson-databind"),
    Fingerprint("org.apache.commons.io", "maven", "commons-io", "commons-io", None, "commons-io", "commons-io"),
    Fingerprint("org.apache.commons.compress", "maven", "commons-compress", "commons_compress", None, "org.apache.commons", "commons-compress"),
    Fingerprint("com.facebook", "maven", "facebook-android-sdk", "facebook-android-sdk", None, "com.facebook.android", "facebook-android-sdk"),
    Fingerprint("com.google.firebase", "maven", "firebase", "firebase", None, "com.google.firebase", "firebase", True),
    Fingerprint("com.google.android.gms", "maven", "play-services", "google_play_services", None, "com.google.android.gms", "play-services", True),
    Fingerprint("kotlin", "maven", "kotlin-stdlib", "kotlin", "cpe:2.3:a:jetbrains:kotlin", "org.jetbrains.kotlin", "kotlin-stdlib", True),
    Fingerprint("androidx", "android", "androidx", "androidx", None, "androidx", None, True),
    Fingerprint("android.support", "android", "support-library", "android_support_library", None, "com.android.support", None, True),
    Fingerprint("com.google.protobuf", "maven", "protobuf-java", "protobuf-java", "cpe:2.3:a:google:protobuf-java", "com.google.protobuf", "protobuf-java"),
    Fingerprint("net.sqlcipher", "maven", "sqlcipher", "sqlcipher", None, "net.zetetic", "android-database-sqlcipher"),
    Fingerprint("com.nostra13.universalimageloader", "maven", "universal-image-loader", "universal-image-loader", None, None, None),
    Fingerprint("com.airbnb.lottie", "maven", "lottie", "lottie", None, "com.airbnb.android", "lottie"),
)


def match_prefix(package: str) -> Fingerprint | None:
    """Return the most specific fingerprint whose prefix the package matches."""
    best: Fingerprint | None = None
    for fp in FINGERPRINTS:
        if package == fp.prefix or package.startswith(fp.prefix + "."):
            if best is None or len(fp.prefix) > len(best.prefix):
                best = fp
    return best
