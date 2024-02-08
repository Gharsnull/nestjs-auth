/**
 * Interface representing the configuration options for authentication.
 * This interface provides settings related to JWT tokens and domain.
 */
export interface AuthConfig {
  /**
   * The secret key used to sign JWT tokens.
   */
  jwtSecret: string;

  /**
   * The duration in seconds for which JWT tokens are valid.
   */
  jwtExpiresIn: number;

  /**
   * The duration in seconds for which JWT refresh tokens are valid.
   */
  jwtRefreshTokenExpiresIn: number;

  /**
   * The domain for which the authentication is configured.
   * Note: This property is currently not being used.
   */
  domain?: string;
}
