import { Module } from '@nestjs/common';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import { PrismaModule } from '../prisma/prisma.module';
import { AuthModule } from './auth/auth.module';
import { JwtModule } from '@nestjs/jwt';
import { MailerModule } from '@nestjs-modules/mailer';





@Module({
  imports: [
    PrismaModule,
    AuthModule,
    JwtModule,
    MailerModule.forRoot({
      transport:{
        host:"smtp-mail.outlook.com",
        port: 587,
        auth:{
          user:"azerq2023@outlook.fr",
          pass:"Mmmm 123456"
        }
      }
     }),

   

  ],
  controllers: [AppController],
  providers: [AppService],
})
export class AppModule {}
