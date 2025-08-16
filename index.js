/**
 * createLoginTracker
 * -------------------
 * Initializes a secure login closure that tracks attempts and locks after limits.
 *
 * Why a closure?
 *  - `attemptCount`, `failCount`, `locked`, and the real `password` live in the outer
 *    function’s scope and are ONLY accessible to the returned inner arrow function.
 *  - This keeps the state private (can’t be tampered with from the outside) 🔒
 *
 * Contract:
 *  - Call the returned function with the user's password attempt (string).
 *  - On each call, `attemptCount` increases by 1 (per lab spec).
 *  - Success within the first 3 calls → "Login successful".
 *  - Failure within the first 3 calls → "Attempt X: Login failed".
 *  - If attempts exceed 3 OR there are 3 failed attempts → lock and always return
 *    "Account locked due to too many failed login attempts".
 *
 * Error Handling:
 *  - Validates `userInfo` at creation.
 *  - Validates `passwordAttempt` on each call. If not a string, returns a helpful
 *    error message (still counts toward attemptCount per the spec).
 *
 * @param {{ username: string, password: string }} userInfo
 * @returns {(passwordAttempt: string) => { ok: boolean, message: string }}
 */
function createLoginTracker(userInfo) {
  // ---- Guard: ensure userInfo is well-formed --------------------------------
  if (
    !userInfo ||
    typeof userInfo.username !== "string" ||
    typeof userInfo.password !== "string"
  ) {
    throw new TypeError("userInfo must be an object with string username and password");
  }

  // ---- Private state (closure) ----------------------------------------------
  const { username, password } = userInfo;
  const MAX_FAILS = 3; // business rule: 3 failed attempts allowed
  let attemptCount = 0; // total number of calls to the inner function
  let failCount = 0;    // number of incorrect password attempts
  let locked = false;   // whether the account is locked (hard gate)
  const LOCK_MSG = "Account locked due to too many failed login attempts";

  // ---- Inner arrow function: handles ONE login attempt ----------------------
  const loginAttempt = (passwordAttempt) => {
    // Rule: every call increments total attempts (even if it’s already locked)
    attemptCount += 1;

    // Hard gate: if we’re already locked, or if we exceeded 3 total calls
    // lock and block immediately (prevents further guessing).
    if (locked || attemptCount > MAX_FAILS) {
      locked = true; // idempotent
      return { ok: false, message: LOCK_MSG };
    }

    // Input validation: attempts should be strings (graceful error)
    if (typeof passwordAttempt !== "string") {
      // We don’t increment failCount here (invalid input ≠ wrong password),
      // but attemptCount already increased per spec.
      return { ok: false, message: "Invalid input: passwordAttempt must be a string" };
    }

    // Success path: exact match
    if (passwordAttempt === password) {
      // Spec: if success within first 3 calls, say "Login successful"
      return { ok: true, message: "Login successful" };
    }

    // Failure path: wrong password → increase fail count and evaluate lock
    failCount += 1;

    // If this was the 3rd failed attempt, lock immediately
    if (failCount >= MAX_FAILS) {
      locked = true;
      return { ok: false, message: LOCK_MSG };
    }

    // Otherwise, inform which attempt failed (use total attempt count)
    return { ok: false, message: `Attempt ${attemptCount}: Login failed` };
  };

  // Expose only the inner arrow function; all state remains private via closure.
  return loginAttempt;
}
