import { AuthService } from './auth.service';
import { PassportStrategy } from '@nestjs/passport';
import { Strategy, VerifyCallback } from 'passport-google-oauth20';
import { config } from 'dotenv';

import { Injectable } from '@nestjs/common';

config();

@Injectable()
export class GoogleStrategy extends PassportStrategy(Strategy, 'google') {
    constructor( private authService : AuthService ) {
        super({
            clientID: '982503971991-gbc7ultgarli6saftcedg04g9ibhgdml.apps.googleusercontent.com',
            clientSecret: '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',
            callbackURL: 'http://localhost:3000/auth/google/redirect',
            scope: ['email', 'profile'],
        });
    }
    async validate(accessToken: string, refreshToken: string, profile: any, done: VerifyCallback): Promise<any> {
        const { name, emails} = profile
        console.log(profile);
        const user = await this.authService.validateUser({
            id : profile.id,
            name: profile.name.givenName,
            email: profile.emails[0].value,
          });
          console.log('Validate');
          console.log(user);
          return user || null;
    }
}