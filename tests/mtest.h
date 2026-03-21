#ifndef MTEST_H
#define MTEST_H

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef void (*mtest_fn)(void);

static int mtest_failures = 0;
static int mtest_assert_failures = 0;
static int mtest_tests_run = 0;
static int mtest_suites_run = 0;

#define MTEST(name) static void name(void)

#define MTEST_ASSERT_TRUE(cond) \
    do { \
        if (!(cond)) { \
            fprintf(stderr, "[FAIL] %s:%d assertion failed: %s\n", __FILE__, __LINE__, #cond); \
            mtest_assert_failures++; \
            return; \
        } \
    } while (0)

#define MTEST_ASSERT_MEM_EQ(expected, actual, len) \
    do { \
        if (memcmp((expected), (actual), (len)) != 0) { \
            fprintf(stderr, "[FAIL] %s:%d memory mismatch\n", __FILE__, __LINE__); \
            mtest_assert_failures++; \
            return; \
        } \
    } while (0)

#define MTEST_BEGIN(argc, argv) \
    do { (void)(argc); (void)(argv); } while (0)

#define MTEST_RUN(fn) \
    do { \
        int before = mtest_assert_failures; \
        mtest_tests_run++; \
        fn(); \
        if (mtest_assert_failures == before) { \
            printf("[PASS] %s\n", #fn); \
        } else { \
            mtest_failures++; \
        } \
    } while (0)

#define MTEST_SUITE(name) static void suite_##name(void)

#define MTEST_SUITE_RUN(name) \
    do { \
        mtest_suites_run++; \
        printf("\n== suite: %s ==\n", #name); \
        suite_##name(); \
    } while (0)

#define MTEST_END() \
    (printf("\nSuites: %d  Tests: %d  Failures: %d\n", mtest_suites_run, mtest_tests_run, mtest_failures), \
     (mtest_failures == 0 ? 0 : 1))

#ifdef __cplusplus
}
#endif

#endif
