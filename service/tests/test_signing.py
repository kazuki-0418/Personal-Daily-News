from app.signing import SIG_LEN, sign_article, verify


SECRET = "test-secret-0123456789abcdef"


def test_round_trip():
    sig = sign_article("article-xyz", SECRET)
    assert verify("article-xyz", sig, SECRET)


def test_deterministic():
    assert sign_article("abc", SECRET) == sign_article("abc", SECRET)


def test_length_matches_contract():
    assert len(sign_article("any", SECRET)) == SIG_LEN


def test_tampered_signature_rejected():
    sig = sign_article("abc", SECRET)
    bad = "X" + sig[1:]
    assert not verify("abc", bad, SECRET)


def test_wrong_article_id_rejected():
    sig = sign_article("abc", SECRET)
    assert not verify("abd", sig, SECRET)


def test_wrong_secret_rejected():
    sig = sign_article("abc", SECRET)
    assert not verify("abc", sig, "different-secret-0123456789abcdef")


def test_golden_vector():
    # Contract shared with the inline signer in daily_news.py. Changing this
    # breaks every in-flight email link, so treat failure as intentional
    # breakage, not a test bug.
    assert sign_article("article-00000000", "fixed-secret-for-vector-test") == "ywXxJiXq6r973y5e42FAVq"
