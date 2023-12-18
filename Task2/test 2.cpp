#include <UnitTest++/UnitTest++.h>
#include "/home/teirusu/code/TiMP/3-2/modMarshCipher.h"
//#include "/home/teirusu/code/TiMP/3-2/modMarshCipher.cpp"

SUITE(KeyTest)
{
    TEST(ValidKey) {
        CHECK_EQUAL("EVIRPT",modMarshCipher("5").encrypt("PRIVET"));
    }
    TEST(LetterInKey) {
        CHECK_THROW(modMarshCipher cp("Б1"),cipher_error);
    }
    TEST(PunctuationInKey) {
        CHECK_THROW(modMarshCipher cp("1,1"),cipher_error);
    }
    TEST(WhitespaceInKey) {
        CHECK_THROW(modMarshCipher cp("1 2"),cipher_error);
    }
    TEST(EmptyKey) {
        CHECK_THROW(modMarshCipher cp(""),cipher_error);
    }
    TEST(WeakKey) {
        CHECK_THROW(modMarshCipher cp("1"),cipher_error);
    }
}

struct KeyB_fixture {
    modMarshCipher * p;
    KeyB_fixture()
    {
        p = new modMarshCipher("5");
    }
    ~KeyB_fixture()
    {
        delete p;
    }
};

SUITE(EncryptTest)
{
    TEST_FIXTURE(KeyB_fixture, UpCaseString) {
        CHECK_EQUAL("EVIIKRIPT",
                    p->encrypt("PRIVETIKI"));
    }
    TEST_FIXTURE(KeyB_fixture, LowCaseString) {
        CHECK_EQUAL("EVIIKRIPT",
                    p->encrypt("privetiki"));
    }
    TEST_FIXTURE(KeyB_fixture, StringWithWhitspaceAndPunct) {
        CHECK_EQUAL("EVIIKRIPT",
                    p->encrypt("PRIVET IKI!!!"));
    }
    TEST_FIXTURE(KeyB_fixture, EmptyString) {
        CHECK_THROW(p->encrypt(""),cipher_error);
    }
    TEST_FIXTURE(KeyB_fixture, NoAlphaString) {
        CHECK_THROW(p->encrypt("1234567"),cipher_error);
    }
    TEST(MaxShiftKey) {
        CHECK_EQUAL("IKITEVIRP",
                    modMarshCipher("9").encrypt("PRIVETIKI"));
    }
}

SUITE(DecryptText)
{
    TEST_FIXTURE(KeyB_fixture, UpCaseString) {
        CHECK_EQUAL("PRIVETIKI",
                    p->decrypt("EVIIKRIPT"));
    }
    TEST_FIXTURE(KeyB_fixture, LowCaseString) {
        CHECK_THROW(p->decrypt("eviikrIPT"),cipher_error);
    }
    TEST_FIXTURE(KeyB_fixture, WhitespaceString) {
        CHECK_THROW(p->decrypt("EVIIKR IPT"),cipher_error);
    }
    TEST_FIXTURE(KeyB_fixture, PunctString) {
        CHECK_THROW(p->decrypt("EVIIKR, IPT"),cipher_error);
    }
    TEST_FIXTURE(KeyB_fixture, EmptyString) {
        CHECK_THROW(p->decrypt(""),cipher_error);
    }
    TEST(MaxShiftKey) {
        CHECK_EQUAL("PRIVETIKI",
                    modMarshCipher("9").decrypt("IKITEVIRP"));
    }
}

int main(int argc, char **argv)
{
    return UnitTest::RunAllTests();
}