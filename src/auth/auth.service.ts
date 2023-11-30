import { BadRequestException, Injectable } from '@nestjs/common';
import { CreateAuthDto } from './dto/create-auth.dto';
import { PrismaService } from 'prisma/prisma.service';
import * as bcrypt from 'bcrypt';
import { JsonWebTokenError, JwtService, TokenExpiredError } from '@nestjs/jwt';
import { MailerService} from '@nestjs-modules/mailer';
import { CreateAuthGoogleDto } from './dto/create-auth-google.dto';
import { EmailAuthDto } from './dto/email-auth.dto';
import { v4 as uuidv4 } from 'uuid';




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
          id : uuidv4(),
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
  let user;

  try {
    console.log(token);
    const decodedToken = await this.jwtService.verifyAsync(token);
    console.log(decodedToken);

    const userId = decodedToken.userId;
    console.log(userId);

    user = await this.prisma.user.findUnique({
      where: { id: userId },
    });
    console.log(user);

    if (!user) {
      throw new BadRequestException('User not found.');
    }

    if (user.isActive) {
      throw new BadRequestException('Account already active.');
    }

    const activated = await this.prisma.user.update({
      where: { id: userId },
      data: { isActive: true },
    });

    if (activated) {
      return { message: 'Account activated successfully.' };
    }
  } catch (error) {
    if (error instanceof TokenExpiredError) {
      throw new BadRequestException('Token expired. A new activation email has been sent.');
    } else if (error instanceof JsonWebTokenError) {
      throw new BadRequestException('Invalid activation token.');
    } else {
      throw new BadRequestException('An error occurred during activation.');
    }
  }
}

async sendBackMailConfirmation(emailDto: EmailAuthDto){
 
  const fondUser = await this.prisma.user.findUnique({where : {email : emailDto.email}} );
  if (!fondUser){
    throw new BadRequestException('Invalid mail');
  }
  
  if(fondUser.isActive){
    throw new BadRequestException('Account already active.');

  }
  if(!fondUser.isActive){
    const token = await this.generateToken(fondUser);
      await this.sendActivationEmail(fondUser.email, token);
      return { message: ' Activation email sent Successfully.' };

  }
  else{
    return { message: ' an error occurred while sending mail.' };

  }
  }









async googleLogin(req){
  if (!req.user) {
    return 'No user from google'
  }
  return {
    message: 'User Info from Google',
    user: req.user
  }}
  
async googleredirect(){
  return 'user redirected successfully '

}

async validateUser(authGoogle: CreateAuthGoogleDto) {
  console.log('AuthService');
  console.log(authGoogle);
  const user = await this.prisma.userGoogle.findUnique({
    where: {
      email: authGoogle.email,
    },
  });
    console.log(user);
  if (user) return user;
  console.log('User not found. Creating...');
  const newUser = this.prisma.userGoogle.create({
    data: {
      id :authGoogle.id,
      name : authGoogle.name,
      email: authGoogle.email
    },
  });
  return newUser;
}

}

