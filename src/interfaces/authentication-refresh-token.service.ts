import { AuthRefreshToken } from './authentication-refresh-token';

/**
 * Interface representing a service responsible for managing refresh tokens.
 * Implement this interface to define your application's token service.
 */
export interface AuthTokenService {
  /**
   * Save a refresh token to the database.
   * @param refreshToken The refresh token to be saved.
   * @returns A promise that resolves with a string representing the saved refresh token.
   */
  saveRefreshToken(refreshToken: AuthRefreshToken): Promise<string>;

  /**
   * Find a refresh token in the database by its token string.
   * By default, the token is only validated by checking if it is non-nullish.
   * If your implementation can return an invalid/expired token, its validation should be handled in `AuthTokenService.validateToken`.
   * @param token The token string of the refresh token to find.
   * @returns A promise that resolves with the found refresh token, if valid.
   */
  findRefreshToken(token: string): Promise<AuthRefreshToken>;

  /**
   * Optional method to add a custom validation on authentication/refresh token.
   * @param authTokenPayload The payload of the authentication token.
   * @param refreshTokenPayload The payload of the associated refresh token.
   * @returns A promise that resolves with a boolean indicating whether the token is valid.
   */
  validateToken?(
    authTokenPayload: unknown,
    refreshTokenPayload: unknown,
  ): Promise<boolean>;
}
