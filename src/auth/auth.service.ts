import { BadRequestException, Injectable } from '@nestjs/common';
import { CreateAuthDto } from './dto/create-auth.dto';
import { UpdateAuthDto } from './dto/update-auth.dto';
import { PrismaService } from 'prisma/prisma.service';
import * as bcrypt from 'bcrypt';
import { JwtService, TokenExpiredError } from '@nestjs/jwt';
import { MailerService} from '@nestjs-modules/mailer';



@Injectable()
export class AuthService {
  constructor(private readonly prisma: PrismaService ,
     private jwtService: JwtService,
     private mailService : MailerService
    ){}

  async hashPassword(password : string){
    const saltOrRounds=10;
    return await bcrypt.hash(password,saltOrRounds);
  }

  async comparePassword(arg :{password : string , hash:string }){
    return await bcrypt.compare(arg.password, arg.hash);

  }

  private isValidEmail(email: string): boolean {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email);
  }
  async generateToken(user: any) {
    const payload = { userId: user.id, email: user.email };
    return this.jwtService.sign(payload); 
  }
  
  async signup(createAuthDto: CreateAuthDto) {
    const { email,name , password} = createAuthDto;
    if (!createAuthDto.email || !createAuthDto.name || !createAuthDto.password) {
      throw new BadRequestException('Email, name, and password are required.');
    }

    if (!this.isValidEmail(createAuthDto.email)) {
      throw new BadRequestException('Invalid email address.');
    }
  
    const userExists = await this.findByEmail(email) ;
    if (userExists) {
      throw new BadRequestException('User already exists with this email address.');
    }
  
    const hashedPassword = await this.hashPassword(password);
    console.log(hashedPassword);
  
      const created = await this.prisma.user.create({
        data: {
          name,
          email,
          password : hashedPassword ,
         
        }
      });
  
  
    if (created) {
      const token = await this.generateToken(created);
      await this.sendActivationEmail(email, token);

      return { message: 'User created. Activation email sent.' };
      
  }
}

async findByEmail(email: string) {
  return this.prisma.user.findUnique({
    where: { email },
  });
}

async sendActivationEmail(email: string, token: string) {
  const url = `http://localhost:3000/auth/activate/${token}`;
  const mail = await this.mailService.sendMail({
    to: email,
    from: 'azerq2023@outlook.fr',
    subject: "Account confirmation",
    html:"<h1>Confirmation Mail</h1> <h2>Welcome</h2><p>To activate your account, please click on this link</p><a href="+url+">Click this </a>"

})
if (mail) {
  return { message: 'Email sent.' };
} else {
  throw new BadRequestException('Email not sent.');
}
}


async activateAccount(token: string) {
  try {
    const decodedToken = this.jwtService.verify(token);

    const userId = decodedToken.userId;
    const user = await this.prisma.user.findUnique({
      where: { id: userId },
    });

    if (!user) {
      throw new BadRequestException('User not found.');
    }

    if (user.isActive) {
      throw new BadRequestException('Account already active.');
    }

    const currentTimestamp = Math.floor(Date.now() / 1000);

    if (decodedToken.exp && decodedToken.exp < currentTimestamp) {
      const newToken = await this.generateToken(user);
      await this.sendActivationEmail(user.email, newToken);
      
      throw new BadRequestException('Token expired. A new activation email has been sent.');
    }

    await this.prisma.user.update({
      where: { id: userId },
      data: { isActive: true },
    });

    return { message: 'Account activated successfully.' };
  } catch (error) {
    if (error instanceof TokenExpiredError) {
      throw new BadRequestException('Token expired. A new activation email has been sent.');
    } else {
      throw new BadRequestException('Invalid activation token.');
    }
  }
}



  }

