#include "memory_log.hpp"
#include "database.hpp"
#include <iostream>

using std::cout;
using std::endl;
using std::boolalpha;

int main()
{
    cout << "Running memory test...\n";
    log_memory_usage(); // Log memory now

    cout << "Running database test...\n";
    Database db;
    bool success;

    cout << "Adding Test User 1" << endl;
    std::string hashed = hash_password("testpassword");
    success = db.add_user("testuser", hashed);
    cout << boolalpha << success << endl;

    cout << "Adding Test User 2 (duplicate username)" << endl;
    success = db.add_user("testuser", hash_password("testpassword2")); // Should fail due to unique username
    cout << boolalpha << success << endl;

    cout << "Checking Test User 1 (username exists?)" << endl;
    bool found = db.check_user("testuser");
    cout << boolalpha << found << endl;

    cout << "Validating Test User 1 (password correct?)" << endl;
    bool valid = db.validate_user("testuser", "testpassword");
    cout << boolalpha << valid << endl;

    cout << "Validating with Wrong Password" << endl;
    bool invalid = db.validate_user("testuser", "wrongpass");
    cout << boolalpha << invalid << endl;

    log_memory_usage(); // Log memory again
    return 0;
}
