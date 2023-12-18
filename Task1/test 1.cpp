#include <UnitTest++/UnitTest++.h>
#include "/home/teirusu/code/TiMP/3-1/modAlphaCipher.h"
//#include "/home/teirusu/code/TiMP/3-1/modAlphaCipher.cpp"

SUITE(KeyTest)
{
    TEST(ValidKey) {
        CHECK_EQUAL("БВГБВ",modAlphaCipher("БВГ").encrypt("ААААА"));
    }
    TEST(LongKey) {
        CHECK_EQUAL("БВГДЕ",modAlphaCipher("БВГДЕЁЖЗИЙ").encrypt("ААААА"));
    }
    TEST(LowCaseKey) {
        CHECK_EQUAL("БВГБВ",modAlphaCipher("бвг").encrypt("ААААА"));
    }
    TEST(DigitsInKey) {
        CHECK_THROW(modAlphaCipher cp("Б1"),cipher_error);
    }
    TEST(PunctuationInKey) {
        CHECK_THROW(modAlphaCipher cp("Б,В"),cipher_error);
    }
    TEST(WhitespaceInKey) {
        CHECK_THROW(modAlphaCipher cp("Б В"),cipher_error);
    }
    TEST(EmptyKey) {
        CHECK_THROW(modAlphaCipher cp(""),cipher_error);
    }
    TEST(WeakKey) {
        CHECK_THROW(modAlphaCipher cp("ААА"),cipher_error);
    }
}

struct KeyB_fixture {
    modAlphaCipher * p;
    KeyB_fixture()
    {
        p = new modAlphaCipher("Б");
    }
    ~KeyB_fixture()
    {
        delete p;
    }
};

SUITE(EncryptTest)
{
    TEST_FIXTURE(KeyB_fixture, UpCaseString) {
        CHECK_EQUAL("ТПМОЧЁМФОБРСБГЕБ",
                    p->encrypt("СОЛНЦЕЛУНАПРАВДА"));
    }
    TEST_FIXTURE(KeyB_fixture, LowCaseString) {
        CHECK_EQUAL("ТПМОЧЁМФОБРСБГЕБ",
                    p->encrypt("солнцелунаправда"));
    }
    TEST_FIXTURE(KeyB_fixture, StringWithWhitspaceAndPunct) {
        CHECK_EQUAL("ТПМОЧЁМФОБРСБГЕБ",
                    p->encrypt("СОЛНЦЕ ЛУНА ПРАВДА!!!"));
    }
    TEST_FIXTURE(KeyB_fixture, EmptyString) {
        CHECK_THROW(p->encrypt(""),cipher_error);
    }
    TEST_FIXTURE(KeyB_fixture, NoAlphaString) {
        CHECK_THROW(p->encrypt("1234567"),cipher_error);
    }
    TEST(MaxShiftKey) {
        CHECK_EQUAL("РНКМХДКТМЯОПЯБГЯ",
                    modAlphaCipher("Я").encrypt("СОЛНЦЕЛУНАПРАВДА"));
    }
}

SUITE(DecryptText)
{
    TEST_FIXTURE(KeyB_fixture, UpCaseString) {
        CHECK_EQUAL("СОЛНЦЕЛУНАПРАВДА",
                    p->decrypt("ТПМОЧЁМФОБРСБГЕБ"));
    }
    TEST_FIXTURE(KeyB_fixture, LowCaseString) {
        CHECK_THROW(p->decrypt("ТПМОЧЁМФОБрсбгеб"),cipher_error);
    }
    TEST_FIXTURE(KeyB_fixture, WhitespaceString) {
        CHECK_THROW(p->decrypt("ТПМОЧЁ МФОБ РСБГЕБ"),cipher_error);
    }
    TEST_FIXTURE(KeyB_fixture, DigitsString) {
        CHECK_THROW(p->decrypt("1234567"),cipher_error);
    }
    TEST_FIXTURE(KeyB_fixture, PunctString) {
        CHECK_THROW(p->decrypt("ТПМОЧЁ, МФОБРСБГЕБ"),cipher_error);
    }
    TEST_FIXTURE(KeyB_fixture, EmptyString) {
        CHECK_THROW(p->decrypt(""),cipher_error);
    }
    TEST(MaxShiftKey) {
        CHECK_EQUAL("СОЛНЦЕЛУНАПРАВДА",
                    modAlphaCipher("Я").decrypt("РНКМХДКТМЯОПЯБГЯ"));
    }
}

int main(int argc, char **argv)
{
    return UnitTest::RunAllTests();
}