import { BadRequestException, ForbiddenException, Injectable, UnauthorizedException } from '@nestjs/common';
import { CreateAuthDto } from './dto/create-auth.dto';
import { PrismaService } from 'prisma/prisma.service';
import * as bcrypt from 'bcrypt';
import { JsonWebTokenError, JwtService, TokenExpiredError } from '@nestjs/jwt';
import { MailerService} from '@nestjs-modules/mailer';
import { CreateAuthGoogleDto } from './dto/create-auth-google.dto';
import { EmailAuthDto } from './dto/email-auth.dto';
import { v4 as uuidv4 } from 'uuid';
import { LoginAuthDto } from './dto/login-auth.dto';
import { Request, Response } from 'express';
import { ResetPasswordDto } from './dto/reset-password.dto';




@Injectable()
export class AuthService {
  constructor(private readonly prisma: PrismaService ,
     private jwtService: JwtService,
     private mailService : MailerService
    ){}


    /******Sign up Methode *********** */
    async signup(createAuthDto: CreateAuthDto)  {
      const { email,name , password} = createAuthDto;
     
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


  /********* encrypt and decrypt password ******* */
  async hashPassword(password : string){
    const saltOrRounds=10;
    return await bcrypt.hash(password,saltOrRounds);
  }

  async comparePassword(arg :{password : string , hash:string }){
    return await bcrypt.compare(arg.password, arg.hash);

  }


  /**********Generate Token ******** */

  async generateToken(user: any) {
    const payload = { userId: user.id, email: user.email };
    return this.jwtService.sign(payload); 
  }
  

  /*********** Activation Account ********* */

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

/******Google Authentification  ***** */
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


/************Sign in *********** */
async signin(loginAuthDto :LoginAuthDto, res : Response) {
  const {email,password}= loginAuthDto
  const fondUser=await this.prisma.user.findUnique({where: {email}})
  if(!fondUser){
    throw new BadRequestException("Please check your information and try again")
  }
  const isMatch =await this.comparePassword({
    password,
    hash:fondUser.password
  });
  if(!isMatch){
    throw new BadRequestException("Please check your information and try again")
  }

  if(!fondUser.isActive ){
    throw new UnauthorizedException("Check your mail for Account Verfication please")
   
  }
  
  
  const token = await this.jwtService.signAsync({id:fondUser.id})
  if (!token){
    throw new ForbiddenException()
    
  }     
  
    res.cookie('token',token)
    
 
 const jwt = { token: token};
   return  jwt;


}

/***************Verfiy User Connected ******* */

async GetUser(req : Request) {
    
  const cookie = req.cookies['token'];
  if(!cookie){
    throw new UnauthorizedException("You are not loggged in");
  }
const data = await this.jwtService.verifyAsync(cookie);

if(!data){
  throw new UnauthorizedException();
}
const user = await this.prisma.user.findUnique({where : {id : data['id']}} );

return {message : "hello "+user.name +" you are logged in"};
}




/**********************Sign out ********* */
signout( res : Response) {
  res.clearCookie('token');
  return res.send({message:'Logged out succefully'});
}

/***************** Fotgot Password  */
async sendResetMail(toemail: string , token : string) {
    
  const mail = await this.mailService.sendMail({
    to: toemail,
      from:"azerq2023@outlook.fr",
      subject: "Reset Password",
      html:"<h1>Reset Password</h1> <h2>Welcome</h2><p>To reset your password, please click on this link</p><a href=http://localhost:3000/auth/resetpassword/"
      +token+">Click this </a>"
     
      
      
  });
  if (mail){
    return {message:"mail sent successfuly"} ; 
  }
  else {
    return {message : "an error occurred while sending mail" } ; 
  }
}

async forgot(emailDto: EmailAuthDto){
  const fondUser=await this.prisma.user.findUnique({where: {email : emailDto.email}})
  
  if (!fondUser){
    throw new BadRequestException('Invalid mail');
  }
  const token =  await this.generateToken(fondUser);
  return await this.sendResetMail(emailDto.email,token);
}

async resetPassword(token : string ,resetPassword: ResetPasswordDto) {
  const decodedToken = await this.jwtService.verifyAsync(token);
    console.log(decodedToken);

    const userId = decodedToken.userId;
  const foundUser = await this.prisma.user.findFirst({ where: { id: userId } });
  if (!foundUser) {
    return {message : "User does not exist" };
  }

  const hashedPassword = await this.hashPassword(resetPassword.password);

  const passwordReset = await this.prisma.user.update({
    where: {
      id: foundUser.id,
    },
    data: {
      password: hashedPassword,
    }
  });
 
  if (!passwordReset) {
    return { message: "Error" };
  }
  return { message: "Your Password Has been Reset Successfully" };
}

}

