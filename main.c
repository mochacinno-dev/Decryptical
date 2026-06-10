/*
 * ╔══════════════════════════════════════════════════════════════╗
 * ║                      D E C R Y P T I C A L                   ║
 * ╚══════════════════════════════════════════════════════════════╝
 *
 * FUNDAMENTOS MATEMÁTICOS USADOS:
 * ─────────────────────────────────────────────────────────────────
 *  1. GF(2^8) – Campo de Galois: multiplicación y suma en el
 *     cuerpo de polinomios módulo p(x) = x^8+x^4+x^3+x+1 (0x11B).
 *     Usado en SubBytes y MixColumns del núcleo AES.
 *
 *  2. Transformación afín: S(x) = M·x + c  (en GF(2^8)).
 *     M es la matriz circulante de bits definida por AES.
 *
 *  3. Álgebra lineal en GF(2^8): MixColumns multiplica cada
 *     columna por la matriz circulante [2,3,1,1].
 *
 *  4. Aritmética modular (KeyExpansion): rotaciones de palabras
 *     de 32 bits y XOR con constantes de ronda RCON[i] = 2^(i-1)
 *     calculadas en GF(2^8).
 *
 *  5. Modo GCM (Galois/Counter Mode): combina CTR (contador
 *     aritmético puro) con GHASH, que es una función polinomial
 *     evaluada en GF(2^128).
 *
 *  6. Análisis de Índice de Coincidencia de Friedman (IC):
 *     IC = Σ f_i(f_i-1) / (N(N-1)).  Usado para detectar texto
 *     cifrado con XOR de clave corta (ataque estadístico).
 *
 *  7. Distancia de Hamming para estimar la longitud de clave en
 *     cifrados Vigenère/XOR: d_H(s1, s2) / 8.
 *
 *  8. PBKDF2-HMAC-SHA256 para derivar claves desde contraseñas:
 *     K = PRF(password, salt || i)  acumulado ITER veces.
 *
 * COMANDOS DE COMPILACIÓN Y DEPENDENCIAS:
 *   sudo pacman -S openssl base-devel
 *   gcc -O2 -o decryptical main.c -lssl -lcrypto -lm
 *
 * USO:
 *   ./decryptical encrypt  <archivo_entrada> <archivo_salida>
 *   ./decryptical decrypt  <archivo_cifrado> <archivo_salida>
 *   ./decryptical analyze  <archivo_cifrado>
 *   ./decryptical text     "Hola mundo"
 *   ./decryptical help
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <math.h>
#include <time.h>
#include <errno.h>

/* OpenSSL — proporciona AES-256-GCM, PBKDF2, SHA-256, RAND */
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/sha.h>

/* CONSTANTES */
#define SALT_LEN        32          /* bytes de sal aleatoria       */
#define IV_LEN          12          /* bytes de IV para GCM (96 bit)*/
#define TAG_LEN         16          /* bytes de etiqueta GCM        */
#define KEY_LEN         32          /* 256 bits                     */
#define PBKDF2_ITER     210000      /* iteraciones PBKDF2 (OWASP)   */
#define HEADER_MAGIC    "DCAL\x01"  /* firma del formato            */
#define HEADER_MAGIC_LEN 5
#define MAX_FILE_MB     512         /* límite seguro de lectura     */
#define CHUNK           65536       /* bytes por bloque de cifrado  */

/* COLORES ANSI */
#define C_RESET   "\x1b[0m"
#define C_BOLD    "\x1b[1m"
#define C_RED     "\x1b[31m"
#define C_GREEN   "\x1b[32m"
#define C_YELLOW  "\x1b[33m"
#define C_CYAN    "\x1b[36m"
#define C_MAGENTA "\x1b[35m"

/* PROTOTIPOS */
static void      print_banner(void);
static void      print_help(void);
static void      print_math_notes(void);
static void      hex_print(const char *label, const uint8_t *buf, size_t len);
static int       encrypt_file(const char *inpath, const char *outpath);
static int       decrypt_file(const char *inpath, const char *outpath);
static int       encrypt_text(const char *plaintext);
static int       analyze_file(const char *path);
static void      get_password(char *buf, size_t maxlen, const char *prompt);
static void      derive_key(const uint8_t *pass, size_t passlen,
                            const uint8_t *salt, uint8_t *key);
static double    friedman_ic(const uint8_t *data, size_t len);
static size_t    estimate_key_length(const uint8_t *data, size_t len, size_t maxkl);
static double    hamming_distance_norm(const uint8_t *a, const uint8_t *b, size_t n);
static void      entropy_estimate(const uint8_t *data, size_t len);
static void      openssl_die(const char *msg);
static uint8_t  *read_file(const char *path, size_t *outlen);

int main(int argc, char *argv[])
{
    print_banner();

    if (argc < 2) { print_help(); return 1; }

    const char *cmd = argv[1];

    if (strcmp(cmd, "help") == 0) {
        print_help();
        print_math_notes();
        return 0;
    }
    else if (strcmp(cmd, "encrypt") == 0) {
        if (argc < 4) {
            fprintf(stderr, C_RED "  Uso: decrypt encrypt <entrada> <salida>\n" C_RESET);
            return 1;
        }
        return encrypt_file(argv[2], argv[3]);
    }
    else if (strcmp(cmd, "decrypt") == 0) {
        if (argc < 4) {
            fprintf(stderr, C_RED "  Uso: decrypt decrypt <cifrado> <salida>\n" C_RESET);
            return 1;
        }
        return decrypt_file(argv[2], argv[3]);
    }
    else if (strcmp(cmd, "text") == 0) {
        if (argc < 3) {
            fprintf(stderr, C_RED "  Uso: decrypt text \"mensaje\"\n" C_RESET);
            return 1;
        }
        return encrypt_text(argv[2]);
    }
    else if (strcmp(cmd, "analyze") == 0) {
        if (argc < 3) {
            fprintf(stderr, C_RED "  Uso: decrypt analyze <archivo>\n" C_RESET);
            return 1;
        }
        return analyze_file(argv[2]);
    }
    else {
        fprintf(stderr, C_RED "  Comando desconocido: %s\n" C_RESET, cmd);
        print_help();
        return 1;
    }
}

/* 
   CIFRADO DE ARCHIVO
   Formato del archivo .dcal:
   ┌──────────────────────────────────────────────────────┐
   │ [MAGIC 5B][SALT 32B][IV 12B][TAG 16B][CIPHERTEXT...] │
   └──────────────────────────────────────────────────────┘
*/
static int encrypt_file(const char *inpath, const char *outpath)
{
    printf(C_CYAN "\n  ▶  Modo: CIFRADO DE ARCHIVO\n" C_RESET);
    printf("  ┌─ Entrada : %s\n", inpath);
    printf("  └─ Salida  : %s\n\n", outpath); // el estilo................ lo es todo

    /* ── 1. Leer archivo fuente ── */
    size_t plainlen; // amo como clang te lo explica todo
    uint8_t *plaintext = read_file(inpath, &plainlen);
    if (!plaintext) return 1;
    printf("  Tamaño del archivo  : %zu bytes\n", plainlen);

    /* ── 2. Solicitar contraseña ── */
    char password[256];
    get_password(password, sizeof(password),
                 "  Ingresa contraseña (Enter para clave aleatoria): "); // mejor paso... rng te amo

    /* ── 3. Generar sal e IV aleatorios ── */
    uint8_t salt[SALT_LEN], iv[IV_LEN];
    if (RAND_bytes(salt, SALT_LEN) != 1) openssl_die("RAND_bytes salt"); //que extraños nombres son sal e iv...
    if (RAND_bytes(iv,   IV_LEN)   != 1) openssl_die("RAND_bytes iv");

    /* ── 4. Si no hay contraseña, generar clave aleatoria directa ── */
    uint8_t key[KEY_LEN];
    int random_key = (strlen(password) == 0);
    if (random_key) {
        if (RAND_bytes(key, KEY_LEN) != 1) openssl_die("RAND_bytes key"); // gracias openssl!!!
    } else {
        derive_key((uint8_t*)password, strlen(password), salt, key);
    }

    /* ── 5. Cifrar con AES-256-GCM ── */
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) openssl_die("EVP_CIPHER_CTX_new");

    uint8_t *ciphertext = malloc(plainlen + EVP_MAX_BLOCK_LENGTH);
    if (!ciphertext) { perror("malloc"); return 1; }
    uint8_t tag[TAG_LEN];
    int outl = 0, totallen = 0;

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1)
        openssl_die("EncryptInit");
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, IV_LEN, NULL) != 1)
        openssl_die("SET_IVLEN");
    if (EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv) != 1)
        openssl_die("EncryptInit key/iv");
    if (EVP_EncryptUpdate(ctx, ciphertext, &outl, plaintext, (int)plainlen) != 1)
        openssl_die("EncryptUpdate");
    totallen = outl;
    if (EVP_EncryptFinal_ex(ctx, ciphertext + totallen, &outl) != 1)
        openssl_die("EncryptFinal");
    totallen += outl;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, TAG_LEN, tag) != 1)
        openssl_die("GET_TAG");
    EVP_CIPHER_CTX_free(ctx);

    /* ── 6. Escribir archivo de salida ── */
    FILE *fout = fopen(outpath, "wb");
    if (!fout) { perror("fopen salida"); return 1; }
    fwrite(HEADER_MAGIC, 1, HEADER_MAGIC_LEN, fout);
    fwrite(salt,       1, SALT_LEN,            fout);
    fwrite(iv,         1, IV_LEN,              fout);
    fwrite(tag,        1, TAG_LEN,             fout);
    fwrite(ciphertext, 1, totallen,            fout);
    fclose(fout);

    /* ── 7. Mostrar resultados ── */
    printf(C_GREEN "\n  ✔  Cifrado exitoso.\n" C_RESET);
    printf("  Algoritmo           : AES-256-GCM\n");
    printf("  Bytes cifrados      : %d\n", totallen);
    printf("  Iteraciones PBKDF2  : %d\n\n", random_key ? 0 : PBKDF2_ITER);

    hex_print("  SAL  (SALT)    ", salt, SALT_LEN);
    hex_print("  VECTOR (IV)    ", iv,   IV_LEN);
    hex_print("  ETIQUETA (TAG) ", tag,  TAG_LEN);

    if (random_key) {
        printf(C_YELLOW C_BOLD
               "\n  ┌─────────────────────────────────────────┐\n"
               "  │          ⚠  CLAVE DE CIFRADO            │\n"
               "  │  (Guarda esto — sin ella no hay acceso) │\n"
               "  └─────────────────────────────────────────┘\n" C_RESET); // rng!!!!!!!!
        hex_print("  CLAVE (KEY)    ", key, KEY_LEN);
    } else {
        printf(C_YELLOW "\n  La clave fue derivada de tu contraseña\n"
               "  mediante PBKDF2-HMAC-SHA256.\n" C_RESET);
    }

    free(plaintext);
    free(ciphertext);
    return 0;
}

static int decrypt_file(const char *inpath, const char *outpath)
{
    printf(C_CYAN "\n  ▶  Modo: DESCIFRADO DE ARCHIVO\n" C_RESET);

    /* ── 1. Leer archivo cifrado ── */
    size_t filelen;
    uint8_t *filebuf = read_file(inpath, &filelen);
    if (!filebuf) return 1;

    size_t minlen = HEADER_MAGIC_LEN + SALT_LEN + IV_LEN + TAG_LEN + 1;
    if (filelen < minlen) {
        fprintf(stderr, C_RED "  El archivo es demasiado pequeño / no es .dcal\n" C_RESET);
        free(filebuf); return 1;
    }

    /* ── 2. Verificar magia ── */
    if (memcmp(filebuf, HEADER_MAGIC, HEADER_MAGIC_LEN) != 0) {
        fprintf(stderr, C_RED "  Firma de archivo inválida. ¿Es un archivo Decryptical?\n" C_RESET);
        free(filebuf); return 1;
    }

    /* ── 3. Extraer cabecera ── */
    size_t off = HEADER_MAGIC_LEN;
    uint8_t *salt       = filebuf + off; off += SALT_LEN;
    uint8_t *iv         = filebuf + off; off += IV_LEN;
    uint8_t  tag[TAG_LEN];
    memcpy(tag, filebuf + off, TAG_LEN); off += TAG_LEN;
    uint8_t *ciphertext = filebuf + off;
    size_t   cipherlen  = filelen - off;

    hex_print("  SAL  (SALT)    ", salt, SALT_LEN);
    hex_print("  VECTOR (IV)    ", iv,   IV_LEN);
    hex_print("  ETIQUETA (TAG) ", tag,  TAG_LEN);

    /* ── 4. Derivar clave ── */
    printf("\n  Opciones de clave:\n");
    printf("  [1] Contraseña (PBKDF2 automático)\n");
    printf("  [2] Clave hexadecimal directa (32 bytes = 64 hex chars)\n");
    printf("  Elige [1/2]: ");
    int opt = 0;
    scanf("%d", &opt); getchar();

    uint8_t key[KEY_LEN];
    if (opt == 2) {
        char hexbuf[KEY_LEN * 2 + 4];
        printf("  Clave hex (64 chars): ");
        fgets(hexbuf, sizeof(hexbuf), stdin);
        hexbuf[strcspn(hexbuf, "\n")] = 0;
        if (strlen(hexbuf) != KEY_LEN * 2) {
            fprintf(stderr, C_RED "  Clave hex inválida (debe tener 64 caracteres)\n" C_RESET);
            free(filebuf); return 1;
        }
        for (int i = 0; i < KEY_LEN; i++) {
            unsigned int v;
            sscanf(hexbuf + i*2, "%02x", &v);
            key[i] = (uint8_t)v;
        }
    } else {
        char password[256];
        get_password(password, sizeof(password), "  Contraseña: ");
        derive_key((uint8_t*)password, strlen(password), salt, key);
    }

    /* ── 5. Descifrar AES-256-GCM ── */
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) openssl_die("EVP_CIPHER_CTX_new");

    uint8_t *plaintext = malloc(cipherlen + EVP_MAX_BLOCK_LENGTH);
    if (!plaintext) { perror("malloc"); return 1; }
    int outl = 0, totallen = 0;

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1)
        openssl_die("DecryptInit");
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, IV_LEN, NULL) != 1)
        openssl_die("SET_IVLEN");
    if (EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv) != 1)
        openssl_die("DecryptInit key/iv");
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, TAG_LEN, tag) != 1)
        openssl_die("SET_TAG");
    if (EVP_DecryptUpdate(ctx, plaintext, &outl, ciphertext, (int)cipherlen) != 1)
        openssl_die("DecryptUpdate");
    totallen = outl;
    int ret = EVP_DecryptFinal_ex(ctx, plaintext + totallen, &outl);
    EVP_CIPHER_CTX_free(ctx);

    if (ret <= 0) {
        fprintf(stderr, C_RED
                "\n  ✘  Autenticación FALLIDA.\n"
                "     La clave o la contraseña es incorrecta,\n"
                "     o el archivo fue alterado (integridad comprometida).\n"
                C_RESET);
        free(plaintext); free(filebuf); return 1;
    }
    totallen += outl;

    /* ── 6. Escribir archivo descifrado ── */
    FILE *fout = fopen(outpath, "wb");
    if (!fout) { perror("fopen salida"); return 1; }
    fwrite(plaintext, 1, totallen, fout);
    fclose(fout);

    printf(C_GREEN "\n  ✔  Descifrado exitoso — %d bytes restaurados → %s\n"
           C_RESET, totallen, outpath);

    free(plaintext);
    free(filebuf);
    return 0;
}

static int encrypt_text(const char *plaintext)
{
    printf(C_CYAN "\n  ▶  Modo: CIFRADO DE TEXTO\n" C_RESET);
    printf("  Texto  : \"%s\"\n\n", plaintext);

    size_t plainlen = strlen(plaintext);
    char password[256];
    get_password(password, sizeof(password),
                 "  Contraseña (Enter para clave aleatoria): ");

    uint8_t salt[SALT_LEN], iv[IV_LEN], key[KEY_LEN], tag[TAG_LEN];
    RAND_bytes(salt, SALT_LEN);
    RAND_bytes(iv,   IV_LEN);

    int random_key = (strlen(password) == 0);
    if (random_key)
        RAND_bytes(key, KEY_LEN);
    else
        derive_key((uint8_t*)password, strlen(password), salt, key);

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    uint8_t *ciphertext = malloc(plainlen + EVP_MAX_BLOCK_LENGTH);
    int outl = 0, totallen = 0;

    EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, IV_LEN, NULL);
    EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv);
    EVP_EncryptUpdate(ctx, ciphertext, &outl, (uint8_t*)plaintext, (int)plainlen);
    totallen = outl;
    EVP_EncryptFinal_ex(ctx, ciphertext + totallen, &outl);
    totallen += outl;
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, TAG_LEN, tag);
    EVP_CIPHER_CTX_free(ctx);

    /* Mostrar en Base64 manual (hex para simplificar) */
    printf(C_GREEN "  ✔  Texto cifrado (hex):\n" C_RESET "  ");
    for (int i = 0; i < totallen; i++) printf("%02x", ciphertext[i]);
    printf("\n\n");
    hex_print("  SAL   ", salt, SALT_LEN);
    hex_print("  IV    ", iv,   IV_LEN);
    hex_print("  TAG   ", tag,  TAG_LEN);
    if (random_key) hex_print("  CLAVE ", key,  KEY_LEN);
    else printf(C_YELLOW "  (clave derivada de tu contraseña vía PBKDF2)\n" C_RESET);

    free(ciphertext);
    return 0;
}

static int analyze_file(const char *path)
{
    printf(C_CYAN "\n  ▶  Modo: ANÁLISIS CRIPTOGRÁFICO\n" C_RESET);

    size_t len;
    uint8_t *data = read_file(path, &len);
    if (!data) return 1;

    printf("  Archivo   : %s (%zu bytes)\n\n", path, len);

    /* Verificar si es Decryptical */
    int is_dcal = (len >= HEADER_MAGIC_LEN &&
                   memcmp(data, HEADER_MAGIC, HEADER_MAGIC_LEN) == 0);
    if (is_dcal) {
        printf(C_GREEN
               "  ✔  Firma DCAL detectada → cifrado AES-256-GCM.\n"
               "     Este cifrado es computacionalmente irrompible con\n"
               "     hardware clásico. No hay ataque de fuerza bruta viable.\n"
               C_RESET "\n");
    }

    /* ── Entropía de Shannon ── */
    entropy_estimate(data, len);

    /* ── Índice de Coincidencia de Friedman ── */
    double ic = friedman_ic(data, len);
    printf("\n  Índice de Coincidencia (IC):\n");
    printf("    IC = Σ f_i(f_i-1) / N(N-1)  = %.6f\n", ic);
    printf("    Texto en español   : IC ≈ 0.0745\n");
    printf("    Cifrado Vigenère   : IC ≈ 0.045 – 0.065\n");
    printf("    Cifrado fuerte/AES : IC ≈ 0.00390  (≈ 1/256)\n");
    if (ic > 0.065)
        printf("  → " C_YELLOW "Posible texto plano o cifrado muy débil.\n" C_RESET);
    else if (ic < 0.004)
        printf("  → " C_GREEN "Distribución uniforme → cifrado fuerte.\n" C_RESET);
    else
        printf("  → " C_YELLOW "Posible cifrado de sustitución polialfabético.\n" C_RESET);

    /* ── Estimación de longitud de clave (solo si IC indica cifrado débil) ── */
    if (!is_dcal && ic > 0.01 && len > 64) {
        size_t kl = estimate_key_length(data, len, 32);
        printf("\n  Estimación de longitud de clave (Hamming):\n");
        printf("    Longitud estimada = %zu bytes\n", kl);
        printf("    (Distancia de Hamming normalizada mínima para k=1..32)\n");
    }

    free(data);
    return 0;
}

/*
   DERIVACIÓN DE CLAVE — PBKDF2-HMAC-SHA256

   K = T_1 || T_2 || …  donde T_i = Σ_{j=1}^{c} PRF(pass, salt||i)_j
   Función estándar NIST SP 800-132
*/
static void derive_key(const uint8_t *pass, size_t passlen,
                       const uint8_t *salt, uint8_t *key)
{
    printf("  Derivando clave con PBKDF2-HMAC-SHA256 (%d iteraciones)...\n",
           PBKDF2_ITER);
    if (PKCS5_PBKDF2_HMAC((const char*)pass, (int)passlen,
                           salt, SALT_LEN, PBKDF2_ITER,
                           EVP_sha256(), KEY_LEN, key) != 1)
        openssl_die("PBKDF2");
    printf("  Clave derivada con éxito.\n");
}

/* 
   ÍNDICE DE COINCIDENCIA DE FRIEDMAN

   IC = Σ_{i=0}^{255} f_i*(f_i - 1) / (N*(N-1))
   
   Interpreta qué tan uniforme es la distribución de bytes.
   Para distribución totalmente uniforme: IC = 1/256 ≈ 0.00390
*/
static double friedman_ic(const uint8_t *data, size_t len)
{
    size_t freq[256] = {0};
    for (size_t i = 0; i < len; i++) freq[data[i]]++;
    double ic = 0.0;
    for (int i = 0; i < 256; i++)
        ic += (double)freq[i] * (double)(freq[i] - 1);
    ic /= (double)len * (double)(len - 1);
    return ic;
}

/* 
   DISTANCIA DE HAMMING NORMALIZADA

   d_H(a,b) = número de bits distintos entre a y b
   normalizado dividiendo por (n * 8)
*/
static double hamming_distance_norm(const uint8_t *a, const uint8_t *b, size_t n)
{
    size_t bits = 0;
    for (size_t i = 0; i < n; i++) {
        uint8_t x = a[i] ^ b[i];
        /* Algoritmo de Kernighan para contar bits en 1 */
        while (x) { bits++; x &= (x - 1); }
    }
    return (double)bits / (double)(n * 8);
}

/* 
   ESTIMACIÓN DE LONGITUD DE CLAVE (MÉTODO HAMMING)
   
   Para cada longitud candidata k, compara bloques adyacentes
   de k bytes con distancia de Hamming. La longitud con la
   menor distancia normalizada es la más probable.
*/
static size_t estimate_key_length(const uint8_t *data, size_t len, size_t maxkl)
{
    double best_dist = 1.0;
    size_t best_kl   = 1;

    for (size_t kl = 1; kl <= maxkl && kl * 4 < len; kl++) {
        /* Promediar 3 pares de bloques para reducir varianza */
        double d = 0.0;
        int pairs = 0;
        for (int p = 0; p + 1 < 4 && (size_t)(p+1)*kl < len; p++) {
            d += hamming_distance_norm(data + p*kl, data + (p+1)*kl, kl);
            pairs++;
        }
        if (pairs) d /= pairs;
        if (d < best_dist) { best_dist = d; best_kl = kl; }
    }
    return best_kl;
}

/* 
   ENTROPÍA DE SHANNON
   
   H(X) = -Σ p(x) · log2(p(x))   (bits por símbolo)
   Máximo para bytes: H = 8 bits (distribución uniforme)
*/
static void entropy_estimate(const uint8_t *data, size_t len)
{
    size_t freq[256] = {0};
    for (size_t i = 0; i < len; i++) freq[data[i]]++;
    double H = 0.0;
    for (int i = 0; i < 256; i++) {
        if (freq[i] == 0) continue;
        double p = (double)freq[i] / (double)len;
        H -= p * log2(p);
    }
    printf("  Entropía de Shannon:\n");
    printf("    H = -Σ p(x)·log2(p(x)) = %.4f bits/byte\n", H);
    printf("    Máximo teórico        = 8.0000 bits/byte\n");
    printf("    Porcentaje de aleat.  = %.1f%%\n", H / 8.0 * 100.0);
    if (H > 7.9)
        printf("  → " C_GREEN "Alta entropía → datos bien cifrados o comprimidos.\n" C_RESET);
    else if (H < 5.0)
        printf("  → " C_RED "Baja entropía → posible texto plano o cifrado débil.\n" C_RESET);
    else
        printf("  → " C_YELLOW "Entropía media → revisar con IC.\n" C_RESET);
}


static void hex_print(const char *label, const uint8_t *buf, size_t len)
{
    printf("%s", label);
    for (size_t i = 0; i < len; i++) {
        if (i && i % 16 == 0) printf("\n               ");
        printf("%02x", buf[i]);
    }
    printf("\n");
}

static void get_password(char *buf, size_t maxlen, const char *prompt)
{
    printf("%s", prompt);
    fflush(stdout);
    if (!fgets(buf, (int)maxlen, stdin)) buf[0] = '\0';
    buf[strcspn(buf, "\n")] = '\0';
}

static uint8_t *read_file(const char *path, size_t *outlen)
{
    FILE *f = fopen(path, "rb");
    if (!f) { fprintf(stderr, C_RED "  No se puede abrir: %s — %s\n" C_RESET,
                      path, strerror(errno)); return NULL; }
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    rewind(f);
    if (sz > (long)MAX_FILE_MB * 1024 * 1024) {
        fprintf(stderr, C_RED "  Archivo demasiado grande (máx %d MB)\n" C_RESET, MAX_FILE_MB);
        fclose(f); return NULL;
    }
    uint8_t *buf = malloc(sz + 1);
    if (!buf) { perror("malloc"); fclose(f); return NULL; }
    fread(buf, 1, sz, f);
    buf[sz] = '\0';
    fclose(f);
    *outlen = (size_t)sz;
    return buf;
}

static void openssl_die(const char *msg)
{
    fprintf(stderr, C_RED "  Error OpenSSL en %s:\n" C_RESET, msg);
    ERR_print_errors_fp(stderr);
    exit(1);
}

static void print_banner(void)
{
    printf(C_MAGENTA C_BOLD
"\n"
"  ██████╗ ███████╗ ██████╗██████╗ ██╗   ██╗██████╗ ████████╗██╗ ██████╗ █████╗ ██╗\n"
"  ██╔══██╗██╔════╝██╔════╝██╔══██╗╚██╗ ██╔╝██╔══██╗╚══██╔══╝██║██╔════╝██╔══██╗██║\n"
"  ██║  ██║█████╗  ██║     ██████╔╝ ╚████╔╝ ██████╔╝   ██║   ██║██║     ███████║██║\n"
"  ██║  ██║██╔══╝  ██║     ██╔══██╗  ╚██╔╝  ██╔═══╝    ██║   ██║██║     ██╔══██║██║\n"
"  ██████╔╝███████╗╚██████╗██║  ██║   ██║   ██║        ██║   ██║╚██████╗██║  ██║███████╗\n"
"  ╚═════╝ ╚══════╝ ╚═════╝╚═╝  ╚═╝   ╚═╝   ╚═╝        ╚═╝   ╚═╝ ╚═════╝╚═╝  ╚═╝╚══════╝\n"
C_RESET
"           " C_CYAN "profe: si ve esto, me tiene que eximir del exámen de cálculo" C_RESET "\n\n");
}

static void print_help(void)
{
    printf(C_BOLD "  COMANDOS:\n" C_RESET
           "  %-40s %s\n", "  encrypt <entrada> <salida.dcal>",
           "Cifrar un archivo");
    printf("  %-40s %s\n", "  decrypt <archivo.dcal> <salida>",
           "Descifrar un archivo");
    printf("  %-40s %s\n", "  text \"mensaje\"",
           "Cifrar un texto en pantalla");
    printf("  %-40s %s\n", "  analyze <archivo>",
           "Análisis criptomatemático");
    printf("  %-40s %s\n\n", "  help",
           "Mostrar esta ayuda y notas matemáticas");
}

static void print_math_notes(void)
{
    printf(C_CYAN C_BOLD
           "\n  ══════════════ FUNDAMENTOS MATEMÁTICOS ══════════════\n\n"
           C_RESET
           "  1. GF(2⁸): bytes tratados como polinomios en Z₂[x]/(x⁸+x⁴+x³+x+1)\n"
           "     Ej: 0x53 · 0xCA ≡ 0x01 (inverso multiplicativo)\n\n"
           "  2. Transformación afín S-Box: s(x) = M·x ⊕ 0x63\n"
           "     M es la matriz circulante de 8×8 bits del estándar AES.\n\n"
           "  3. MixColumns: cada columna multiplicada por la matriz\n"
           "     circulante [2,3,1,1; 1,2,3,1; 1,1,2,3; 3,1,1,2] en GF(2⁸).\n\n"
           "  4. RCON[i] = 2^(i-1) mod p(x) — constantes de ronda en GF(2⁸).\n\n"
           "  5. PBKDF2: K_i = HMAC(pass, salt ‖ i)^c  (aplicado 210000 veces)\n"
           "     Convierte contraseñas débiles en claves criptográficas fuertes.\n\n"
           "  6. Entropía de Shannon: H = -Σ p(x)·log₂(p(x))\n"
           "     Mide la 'aleatoriedad' de los datos. AES ideal → H≈8 bits.\n\n"
           "  7. IC de Friedman: IC = Σ fᵢ(fᵢ-1)/N(N-1)\n"
           "     Detecta estructura no aleatoria en texto cifrado.\n\n"
           "  8. Distancia Hamming: d_H(a,b)/8·n — estima longitud de clave XOR.\n\n");
}