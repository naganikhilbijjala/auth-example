import { Injectable, UnauthorizedException } from '@nestjs/common';
import { UsersService } from 'src/users/users.service';

type AuthInput = { username: string; password: string };
type SignInData = { userId: number; username: string };
type AuthResult = { accessToken: string; userId: number; username: string };

@Injectable()
export class AuthService {
  constructor(private userService: UsersService) {}
  authenticate(input: AuthInput): AuthResult {
    const user = this.validateUser(input);
    if (!user) {
      throw new UnauthorizedException();
    }

    return {
      accessToken: 'fake-jwt-token', // In a real application, generate a JWT token here
      userId: user.userId,
      username: user.username,
    };
  }

  validateUser(input: AuthInput): SignInData | null {
    const user = this.userService.findUserByName(input.username);
    if (user && user.password === input.password) {
      return {
        userId: user.userId,
        username: user.username,
      };
    }
    return null;
  }
}
