#define handle_error(S, M) if ((S) == -1) {fprintf(stderr, " Line %d ", __LINE__); perror(M); exit(EXIT_FAILURE);}
#define handle_null(S, M) if ((S) == NULL) {fprintf(stderr, " Line %d ", __LINE__); perror(M); exit(EXIT_FAILURE);}
#define handle_null_ssl(S, M) if ((S) == NULL) {fprintf(stderr, " Line %d ", __LINE__); perror(M); ERR_print_errors_fp(stderr); exit(EXIT_FAILURE);}
#define handle_negative_ssl(S, M) if ((S) <= 0) {fprintf(stderr, " Line %d ", __LINE__); perror(M); ERR_print_errors_fp(stderr); exit(EXIT_FAILURE);}
#define handle_zero(S, M) if ((S) == 0) {fprintf(stderr, " Line %d ", __LINE__); perror(M); exit(EXIT_FAILURE);}
#define handle_minus_one(S, M) if ((S) == -1) {fprintf(stderr, " Line %d ", __LINE__); perror(M); exit(EXIT_FAILURE);}
#define handle_not_minus_one(S, M) if ((S) != -1) {fprintf(stderr, " Line %d ", __LINE__); perror(M); exit(EXIT_FAILURE);}