/**
 * Interface representing a refresh token used for authentication token refreshing.
 * This token is used to extend the session and generate new access tokens.
 */
export interface AuthRefreshToken {
  /**
   * The refresh token string
   * Contains all the payload returned from AuthUserService.getUserDataForToken.
   */
  token: string;

  /**
   * The timestamp indicating when the refresh token was created.
   */
  createdAt: Date;

  /**
   * The timestamp indicating when the refresh token expires.
   * After this time, the token should either be deleted or no longer considered valid.
   */
  expireAt: Date;
}
