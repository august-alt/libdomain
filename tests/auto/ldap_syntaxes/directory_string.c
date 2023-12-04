#include "ldap_syntax_tests.h"
#include <ldap_syntaxes.h>
#include <common.h>

#define number_of_elements(x)  (sizeof(x) / sizeof((x)[0]))

typedef struct testcase_s
{
    char* name;
    char* value;
} testcase_t;

static const testcase_t VALID_VALUES[] =
{
    { "DirectoryString - Positive Test #1: Underscore", "abcd" },
    { "DirectoryString - Positive Test #2: Upperscore", "ABCD" },
    { "DirectoryString - Positive Test #3: Special characters", "!@#$%^&*()_+{}|:<>?:" },
    { "DirectoryString - Positive Test #4: Numbers", "0123456789" },
};
static const int NUMBER_OF_VALID_VALUES = number_of_elements(VALID_VALUES);

static const testcase_t INVALID_VALUES[] =
{
    { "DirectoryString - Negative Test #1: NULL value", NULL },
    { "DirectoryString - Negative Test #2: Empty string", "" }
};
static const int NUMBER_OF_INVALID_VALUES = number_of_elements(INVALID_VALUES);

Ensure(validate_directory_string_returns_true_on_valid_values) {
    for (int i = 0; i < NUMBER_OF_VALID_VALUES; ++i)
    {
        bool rc = validate_directory_string(VALID_VALUES[i].value);

        if (rc != true)
        {
            error("%s - Failed.\n", VALID_VALUES[i].name);
        }
        else
        {
            info("%s - Passed.\n", VALID_VALUES[i].name);
        }

        assert_that(rc, is_true);
    }
}

Ensure(validate_directory_string_returns_false_on_invalid_values) {
    for (int i = 0; i < NUMBER_OF_INVALID_VALUES; ++i)
    {
        bool rc = validate_directory_string(INVALID_VALUES[i].value);

        if (rc != false)
        {
            error("%s - Failed.\n", INVALID_VALUES[i].name);
        }
        else
        {
            info("%s - Passed.\n", INVALID_VALUES[i].name);
        }

        assert_that(rc, is_false);
    }
}

TestSuite* directory_string_test_suite()
{
    TestSuite *suite = create_test_suite();
    add_test(suite, validate_directory_string_returns_true_on_valid_values);
    add_test(suite, validate_directory_string_returns_false_on_invalid_values);
    return suite;
}
