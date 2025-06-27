#include "database.hpp"
#include "argon2.h"
#include <iostream>
#include <random>
#include <stdexcept>
#include <string>


using std::cerr;
using std::cout;
using std::endl;

Database::Database(const std::string &db_path)
{
    if (sqlite3_open(db_path.c_str(), &db) != SQLITE_OK)
    {
        cerr << "Error opening database: " << sqlite3_errmsg(db) << endl;
        db = nullptr;
        exit(EXIT_FAILURE);
    }

    const char *create_table_sql = "CREATE TABLE IF NOT EXISTS users ("
                                   "id INTEGER PRIMARY KEY AUTOINCREMENT, "
                                   "username TEXT UNIQUE NOT NULL, "
                                   "password_hash TEXT NOT NULL);";
    char *err_msg = nullptr;
    if (sqlite3_exec(db, create_table_sql, nullptr, nullptr, &err_msg) != SQLITE_OK)
    {
        cerr << "Error creating table: " << err_msg << endl;
        sqlite3_free(err_msg);
        sqlite3_close(db);
        db = nullptr;
    }
}

Database::~Database()
{
    if (db)
    {
        sqlite3_close(db);
    }
}

bool Database::check_user(const std::string &username)
{
    if (!db)
        exit(EXIT_FAILURE);

    const char *sql = "SELECT 1 FROM users WHERE username = ?;";
    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK)
    {
        cerr << "Error preparing statement: " << sqlite3_errmsg(db) << endl;
        exit(EXIT_FAILURE);
    }

    sqlite3_bind_text(stmt, 1, username.c_str(), -1, SQLITE_STATIC);
    bool exists = (sqlite3_step(stmt) == SQLITE_ROW);
    sqlite3_finalize(stmt);
    return exists;
}

bool Database::add_user(const std::string &username, const std::string &password_hash)
{
    if (!db)
        exit(EXIT_FAILURE);

    if (check_user(username))
        return false; // User already exists

    const char *sql = "INSERT INTO users (username, password_hash) VALUES (?, ?);";
    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK)
    {
        cerr << "Error preparing statement: " << sqlite3_errmsg(db) << endl;
        exit(EXIT_FAILURE);
    }

    sqlite3_bind_text(stmt, 1, username.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, password_hash.c_str(), -1, SQLITE_STATIC);

    bool success = (sqlite3_step(stmt) == SQLITE_DONE);
    sqlite3_finalize(stmt);
    return success;
}

bool Database::validate_user(const std::string &username, const std::string &password)
{
    if (!db)
        exit(EXIT_FAILURE);

    const char *sql = "SELECT password_hash FROM users WHERE username = ?;";
    sqlite3_stmt *stmt;

    if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK)
    {
        cerr << "Error preparing statement: " << sqlite3_errmsg(db) << endl;
        exit(EXIT_FAILURE);
    }

    sqlite3_bind_text(stmt, 1, username.c_str(), -1, SQLITE_STATIC);

    bool valid = false;

    if (sqlite3_step(stmt) == SQLITE_ROW)
    {
        const unsigned char *stored_hash = sqlite3_column_text(stmt, 0);
        if (stored_hash != nullptr)
        {
            valid = verify_password(password, reinterpret_cast<const char *>(stored_hash));
        }
    }

    sqlite3_finalize(stmt);
    return valid;
}

std::string generate_salt(size_t length) {
    std::string salt;
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dist(33, 126); // printable ASCII range

    for (size_t i = 0; i < length; ++i) {
        salt += static_cast<char>(dist(gen));
    }
    return salt;
}

std::string hash_password(const std::string &password) {
    std::string salt = generate_salt();
    const size_t hash_len = 32;         // length of the raw hash
    const size_t encoded_len = 108;     // length of the encoded hash string
    char encoded[encoded_len];

    int result = argon2i_hash_encoded(
        2,           // time cost (iterations)
        1 << 16,     // memory cost (64 MB)
        1,           // parallelism
        password.data(),
        password.size(),
        reinterpret_cast<const uint8_t *>(salt.data()),
        salt.size(),
        hash_len,
        encoded,
        encoded_len
    );

    if (result != ARGON2_OK) {
        throw std::runtime_error(argon2_error_message(result));
    }

    return std::string(encoded);  // store this string in the database
}

bool verify_password(const std::string &password, const std::string &encoded_hash) {
    int result = argon2i_verify(
        encoded_hash.c_str(),
        password.c_str(),
        password.size()
    );

    return (result == ARGON2_OK);
}