from haul.links import (
    DL_RE,
    FILE_HINT_RE,
    LINK_RE,
    archive_base,
    duration,
    folder_name,
    human_size,
    name_from_url,
    page_key,
    safe_name,
)


def test_link_re_finds_page_links_in_html():
    html = ('<a href="https://fuckingfast.co/abc123#Jeu--fitgirl.part01.rar">Jeu.part01.rar</a>'
            '<a href="https://fuckingfast.co/f/x_y-Z">autre</a>'
            '<a href="https://dl.fuckingfast.co/dl/tok">direct</a>'
            '<a href="https://fuckingfast.co/dl/old">ancien direct</a>')
    assert [m.group(0) for m in LINK_RE.finditer(html)] == [
        "https://fuckingfast.co/abc123#Jeu--fitgirl.part01.rar",
        "https://fuckingfast.co/f/x_y-Z",
    ]


def test_dl_re_accepts_current_and_legacy_direct_links():
    assert DL_RE.fullmatch("https://dl.fuckingfast.co/dl/PzxLnrPVnC_UnTl-Si")
    assert DL_RE.fullmatch("https://fuckingfast.co/dl/abc")
    assert not DL_RE.fullmatch("https://evil.example/dl/abc")
    assert not DL_RE.fullmatch("https://fuckingfast.co/abc")


def test_name_from_url_uses_fragment():
    assert name_from_url("https://fuckingfast.co/a#My%20Game%3A%20X.part01.rar") == "My Game_ X.part01.rar"
    assert name_from_url("https://fuckingfast.co/a") is None


def test_page_key_ignores_fragment_www_and_f_prefix():
    keys = {page_key(u) for u in ("https://fuckingfast.co/abc#x.rar", "https://www.fuckingfast.co/abc",
                                  "https://fuckingfast.co/f/abc/")}
    assert keys == {"fuckingfast.co/abc"}


def test_safe_name_and_human_size():
    assert safe_name('a<b>:c"d|e?.rar') == "a_b__c_d_e_.rar"
    assert safe_name(" .. ") is None
    assert human_size(512) == "512 o"
    assert human_size(3 << 30) == "3.0 Go"


def test_file_hint_detects_names_without_links():
    assert FILE_HINT_RE.search("Jeu--fitgirl-repacks.site--.part01.rar")
    assert not FILE_HINT_RE.search("bonjour")


def test_safe_name_avoids_windows_device_names():
    assert safe_name("CON.rar") == "_CON.rar"
    assert safe_name("nul") == "_nul"
    assert safe_name("com1.part01.rar") == "_com1.part01.rar"
    assert safe_name("CONSOLE.rar") == "CONSOLE.rar"


def test_folder_name_from_archive_name():
    assert folder_name("Elden_Ring_--_fitgirl-repacks.site_--_.part01.rar") == "Elden Ring"
    assert folder_name("Jeu Deluxe.part3.rar") == "Jeu Deluxe"
    assert folder_name("Bonus.rar") == "Bonus"
    assert folder_name("fg-optional-bonus.bin") is None
    assert folder_name(None) is None
    assert archive_base("Jeu.part02.rar") == "Jeu"


def test_duration():
    assert [duration(s) for s in (0, 45, 90, 3599, 3600, 7500)] == ["0 s", "45 s", "2 min", "1 h 00", "1 h 00",
                                                                    "2 h 05"]
