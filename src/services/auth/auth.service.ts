import {
  Inject,
  Injectable,
  NotFoundException,
  UnauthorizedException,
} from '@nestjs/common';
import {
  AUTHENTICATION_CONFIG_TOKEN,
  AUTHENTICATION_TOKEN_SERVICE_TOKEN,
  INVALID_CREDENTIALS,
  SESSION_TIME_OUT,
  USER_SERVICE_TOKEN,
} from '../../constants';
import {
  AuthConfig,
  AuthRefreshToken,
  AuthTokenService,
  AuthUser,
  AuthUserService,
  LogInPayload,
} from '../../interfaces';
import { JwtService } from '@nestjs/jwt';
import { USER_NOT_FOUND } from '../../constants';
import { suid } from 'rand-token';
import * as bcrypt from 'bcrypt';

/**
 * Service responsible for handling authentication operations such as logging in and session refreshing.
 * @template T The type of the user model implementing AuthUser.
 */
@Injectable()
export class AuthService<T extends AuthUser> {
  constructor(
    @Inject(AUTHENTICATION_TOKEN_SERVICE_TOKEN)
    private readonly tokenService: AuthTokenService,
    @Inject(AUTHENTICATION_CONFIG_TOKEN)
    private readonly config: AuthConfig,
    @Inject(USER_SERVICE_TOKEN)
    private readonly userService: AuthUserService<T>,
    private readonly jwtService: JwtService,
  ) {}

  /**
   * Authenticates a user using the provided login payload.
   * @param payload The login payload containing user email and password.
   * @returns A promise that resolves with authentication tokens (authToken and refreshToken).
   * @throws {NotFoundException} If the user with the provided email is not found.
   * @throws {UnauthorizedException} If the provided password is incorrect or authentication fails.
   */
  async logIn(payload: LogInPayload) {
    const user = await this.userService.findByEmail(payload.email);

    if (!user) {
      throw new NotFoundException(USER_NOT_FOUND);
    }

    const passwordMatch = await bcrypt.compare(payload.password, user.password);
    if (!passwordMatch) {
      throw new UnauthorizedException(INVALID_CREDENTIALS);
    }

    if (this.userService.validateAuthUser) {
      const isValid = await this.userService.validateAuthUser(user, payload);
      if (!isValid) {
        throw new UnauthorizedException(INVALID_CREDENTIALS);
      }
    }

    const tokenPayload = await this.userService.getUserDataForToken(user);

    const authToken = this.jwtService.sign(tokenPayload);
    const refreshToken = await this.createRefreshToken();

    return {
      authToken,
      refreshToken,
    };
  }

  /**
   * Refreshes a user's session using the provided authentication and refresh tokens.
   * @param authToken The current authentication token.
   * @param refreshToken The refresh token associated with the user's session.
   * @returns A promise that resolves with a new authentication token and the unchanged refresh token.
   * @throws {UnauthorizedException} If the provided refresh token is invalid or session time has expired.
   */
  async refreshSession(authToken: string, refreshToken: string) {
    const refreshTokenPayload = await this.checkSession(
      authToken,
      refreshToken,
    );

    const authTokenPayload = this.getTokenPayload(authToken);
    const newAuthToken = this.jwtService.sign(authTokenPayload);

    refreshTokenPayload.expireAt = this.getTokenExpiration();
    await this.tokenService.saveRefreshToken(refreshTokenPayload);

    return {
      newAuthToken,
      refreshToken,
    };
  }

  /**
   * Checks the validity of a user's session using the provided authentication and refresh tokens.
   * @param authToken The current authentication token.
   * @param refreshToken The refresh token associated with the user's session.
   * @returns A promise that resolves with the refresh token payload if the session is valid.
   * @throws {UnauthorizedException} If the provided refresh token is invalid or session time has expired.
   */
  async checkSession(
    authToken: string,
    refreshToken: string,
  ): Promise<AuthRefreshToken> {
    if (!refreshToken) {
      throw new UnauthorizedException();
    }

    const token = await this.tokenService.findRefreshToken(refreshToken);

    if (!token) {
      throw new UnauthorizedException(SESSION_TIME_OUT);
    }

    if (this.tokenService.validateToken) {
      const authTokenPayload = this.getTokenPayload(authToken);

      const isValid = await this.tokenService.validateToken(
        authTokenPayload,
        token,
      );
      if (!isValid) {
        throw new UnauthorizedException(INVALID_CREDENTIALS);
      }
    }

    return token;
  }

  /**
   * Extracts the payload from an authentication token.
   * @param token The authentication token from which to extract the payload.
   * @returns The payload extracted from the authentication token.
   */
  private getTokenPayload(token: string) {
    const rawToken = token.replace('Bearer ', '');
    return this.jwtService.verify(rawToken, {
      secret: this.config.jwtSecret,
    });
  }

  /**
   * Creates a new refresh token and saves it to the token service.
   * @returns A promise that resolves with the newly created refresh token.
   */
  private async createRefreshToken(): Promise<string> {
    const token = suid(32);
    const currentDate = new Date();
    const expireAt = this.getTokenExpiration();

    await this.tokenService.saveRefreshToken({
      token,
      expireAt,
      createdAt: currentDate,
    });
    return token;
  }

  /**
   * Calculates the expiration date for a refresh token.
   * @returns The expiration date for the refresh token.
   */
  private getTokenExpiration(): Date {
    const currentDate = new Date();
    const expireAt = new Date(
      currentDate.getTime() + this.config.jwtRefreshTokenExpiresIn * 1000,
    );
    return expireAt;
  }
}
