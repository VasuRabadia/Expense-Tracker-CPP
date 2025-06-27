#ifndef DATABSE_HPP
#define DATABSE_HPP

#include <string>
#include <sqlite3.h>

class Database
{
public:
    Database(const std::string &db_path = "../data/main.db");
    ~Database();

    bool check_user(const std::string &username);
    bool add_user(const std::string &username, const std::string &password_hash);
    bool validate_user(const std::string &username, const std::string &password_hash);

private:
    sqlite3 *db;
};

std::string generate_salt(size_t length = 16);
std::string hash_password(const std::string &simple_password);
bool verify_password(const std::string &password, const std::string &encoded_hash);

#endif