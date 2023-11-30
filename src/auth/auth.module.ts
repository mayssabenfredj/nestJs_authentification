import { Module } from '@nestjs/common';
import { AuthService } from './auth.service';
import { AuthController } from './auth.controller';
import { JwtModule } from '@nestjs/jwt';
import { GoogleStrategy } from './google.strategy';



@Module({
  imports: [
    JwtModule.register({
      global: true,
      secret: 'signup',
      signOptions: { expiresIn: '1h' },
    }),
  ],

  controllers: [AuthController],
  providers: [AuthService , GoogleStrategy]
})
export class AuthModule {}
