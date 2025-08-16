/**
 * Secure login with closures + arrow function
 * - Increments attemptCount on every call
 * - Success: "Login successful" if correct (and attemptCount <= 3)
 * - Failure: "Attempt X: Login failed" (while not locked and attemptCount <= 3)
 * - Lock if failCount >= 3 OR attemptCount > 3
 */
function createLoginTracker(userInfo) {
  if (
    !userInfo ||
    typeof userInfo.username !== "string" ||
    typeof userInfo.password !== "string"
  ) {
    throw new TypeError("userInfo must be an object with string username and password");
  }

  const { username, password } = userInfo;

  let attemptCount = 0;   // total calls
  let failCount = 0;      // failed tries
  const MAX_FAILS = 3;
  let locked = false;

  const LOCK_MSG = "Account locked due to too many failed login attempts";

  // inner arrow function handling each attempt
  const attemptLogin = (passwordAttempt) => {
    attemptCount += 1; // always bump first

    // hard lock if already locked OR we’ve exceeded 3 total attempts
    if (locked || attemptCount > MAX_FAILS) {
      locked = true;
      return { ok: false, message: LOCK_MSG };
    }

    // correct password
    if (passwordAttempt === password) {
      return { ok: true, message: "Login successful" };
    }

    // incorrect password
    failCount += 1;

    // lock after third failed attempt
    if (failCount >= MAX_FAILS) {
      locked = true;
      return { ok: false, message: LOCK_MSG };
    }

    return { ok: false, message: `Attempt ${attemptCount}: Login failed` };
  };

  return attemptLogin;
}
