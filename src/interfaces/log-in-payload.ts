/**
 * Interface representing the payload for user login credentials.
 * This interface defines the structure of the data required for logging in.
 */
export interface LogInPayload {
  /**
   * The email address of the user attempting to log in.
   */
  email: string;

  /**
   * The password of the user attempting to log in.
   */
  password: string;
}
