#pragma once

#include "core/account_store/account.hpp"

namespace sam::core {

// Only a definitive authentication refusal makes a refresh token unusable.
// EResult 6 (LoggedInElsewhere), timeouts, connection failures, and GC errors
// must NOT erase credentials: the server never established that they were bad.
inline bool is_rejected_login_token(int eresult) {
    return eresult == 5   // InvalidPassword / invalid login token
        || eresult == 15  // AccessDenied
        || eresult == 27; // Expired
}

// Forget credentials only, not the account, password, profile or Steam Guard.
// A failed token-only (NFA) login needs a new imported token; a password account
// can mint a fresh SteamClient token using its saved credentials.
inline void forget_rejected_login_token(Account& a) {
    if (a.is_nfa) {
        if (!a.refresh_token.empty())
            crypto::zero_buffer(a.refresh_token.data(), a.refresh_token.size());
        a.refresh_token.clear();
        a.refresh_token_expires = 0;
        a.nfa_status = NfaTokenStatus::Revoked;
    } else {
        if (!a.cm_refresh_token.empty())
            crypto::zero_buffer(a.cm_refresh_token.data(), a.cm_refresh_token.size());
        a.cm_refresh_token.clear();
        a.cm_refresh_token_expires = 0;
        a.cm_status = NfaTokenStatus::Revoked;
    }
}

} // namespace sam::core
