/**
 * Interface representing the user model used for authentication.
 * Extend this interface to define your application's user model.
 */
export interface AuthUser {
  /** Unique identifier for the user. */
  id: string;
  /** Email address of the user. */
  email: string;
  /** Password of the user (hashed or encrypted). */
  password: string;
}
