import { DynamicModule, Module } from '@nestjs/common';
import {
  AuthConfig,
  AuthTokenService,
  AuthUser,
  AuthUserService,
} from './interfaces';
import { PassportModule } from '@nestjs/passport';
import { JwtModule, JwtModuleOptions } from '@nestjs/jwt';
import {
  AUTHENTICATION_CONFIG_TOKEN,
  AUTHENTICATION_TOKEN_SERVICE_TOKEN,
  USER_SERVICE_TOKEN,
} from './constants';
import { AuthService } from './services/auth/auth.service';

/**
 * Module responsible for providing authentication-related services and utilities.
 * It includes an authentication service, token management, and configuration options.
 */
@Module({
  providers: [AuthService],
})
export class AuthModule {
  /**
   * Creates a dynamic module for the authentication module with custom configuration options.
   * @template TUser The type of the user model implementing AuthUser.
   * @param options The configuration options for authentication.
   * @param userService The service responsible for managing users.
   * @param tokenService The service responsible for managing authentication tokens.
   * @returns A dynamic module that can be imported into the application.
   */
  static forRoot<TUser extends AuthUser>(
    options: AuthConfig,
    userService: AuthUserService<TUser>,
    tokenService: AuthTokenService,
  ): DynamicModule {
    const jwtOptions: JwtModuleOptions = {
      secret: options.jwtSecret,
      signOptions: {
        expiresIn: options.jwtExpiresIn,
      },
    };

    return {
      module: AuthModule,
      imports: [
        PassportModule.register({ defaultStrategy: 'jwt', session: false }),
        JwtModule.register(jwtOptions),
      ],
      providers: [
        {
          provide: USER_SERVICE_TOKEN,
          useValue: userService,
        },
        {
          provide: AUTHENTICATION_CONFIG_TOKEN,
          useValue: options,
        },
        {
          provide: AUTHENTICATION_TOKEN_SERVICE_TOKEN,
          useValue: tokenService,
        },
      ],
      exports: [],
    };
  }
}
