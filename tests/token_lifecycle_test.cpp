// Small standalone regression test for login-token invalidation policy.
// Build with the project's normal include paths and C++20 enabled.
#include <cassert>
#include "core/account_store/token_lifecycle.hpp"

int main() {
    using namespace sam;
    assert(!core::is_rejected_login_token(0)); // no Steam response
    assert(!core::is_rejected_login_token(1)); // accepted
    assert(!core::is_rejected_login_token(6)); // other session playing
    assert(!core::is_rejected_login_token(84)); // rate limiting
    assert(core::is_rejected_login_token(5)); // invalid credential
    assert(core::is_rejected_login_token(15)); // access denied
    assert(core::is_rejected_login_token(27)); // expired

    core::Account nfa;
    nfa.is_nfa = true;
    nfa.refresh_token = crypto::make_secure("invalid-nfa-token");
    nfa.refresh_token_expires = 123;
    nfa.password = crypto::make_secure("untouched-password");
    core::forget_rejected_login_token(nfa);
    assert(nfa.refresh_token.empty());
    assert(nfa.refresh_token_expires == 0);
    assert(nfa.nfa_status == core::NfaTokenStatus::Revoked);
    assert(!nfa.password.empty());

    core::Account full;
    full.is_nfa = false;
    full.refresh_token = crypto::make_secure("mobile-session-token");
    full.cm_refresh_token = crypto::make_secure("rejected-client-token");
    full.cm_refresh_token_expires = 999;
    full.password = crypto::make_secure("stored-password");
    core::forget_rejected_login_token(full);
    assert(full.cm_refresh_token.empty());
    assert(full.cm_refresh_token_expires == 0);
    assert(full.cm_status == core::NfaTokenStatus::Revoked);
    assert(!full.password.empty());
    assert(!full.refresh_token.empty()); // preserve independent mobile session
}
