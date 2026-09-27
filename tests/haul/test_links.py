from haul.links import DL_RE, FILE_HINT_RE, LINK_RE, human_size, name_from_url, page_key, safe_name


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
