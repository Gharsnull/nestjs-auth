import { AuthUser } from './authentication-user';
import { LogInPayload } from './log-in-payload';

/**
 * Interface representing a service responsible for managing user-related operations.
 * Implement this interface to define your application's user service.
 * @template T The type of the user model extending AuthUser.
 */
export interface AuthUserService<T extends AuthUser> {
  /**
   * Find a user by their email address.
   * @param email The email address of the user to find.
   * @returns A promise that resolves with the found user.
   */
  findByEmail(email: string): Promise<T>;

  /**
   * Get user data required for generating authentication tokens.
   * All the data returned here will be included in the authentication token payload.
   * @param user Optional. The user for which to retrieve data.
   * @returns A promise that resolves with an object containing user data.
   */
  getUserDataForToken(user?: T): Promise<object>;

  /**
   * Optional method to validate a user's authentication credentials.
   * In case you need to perform additional validation on the user's credentials, implement this method.
   * @param user Optional. The user for which to validate credentials.
   * @param payload Optional. The login payload containing user credentials.
   * @returns A promise that resolves with a boolean indicating whether the credentials are valid.
   */
  validateAuthUser?(user?: T, payload?: LogInPayload): Promise<boolean>;
}
