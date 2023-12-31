import { Controller, Get, Post, Body, Query, UseGuards, Req, Res } from '@nestjs/common';
import { AuthService } from './auth.service';
import { CreateAuthDto } from './dto/create-auth.dto';
import { AuthGuard } from '@nestjs/passport'


import { UpdateAuthDto } from './dto/update-auth.dto';
import { EmailAuthDto } from './dto/email-auth.dto';
import { LoginAuthDto } from './dto/login-auth.dto';
import { ResetPasswordDto } from './dto/reset-password.dto';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post('signup')
  signup(@Body() createAuthDto: CreateAuthDto ) {
   
    return this.authService.signup(createAuthDto);
    

  }

  @Get('activate')
  async activateAccount(@Query('token') token: string) {
    return this.authService.activateAccount(token);
  }
  @Post('sendBackMailConfirmation')
  sendBackMailConfirmation(@Body() emailDto: EmailAuthDto) {
    return this.authService.sendBackMailConfirmation(emailDto);
  }



  @Get('google/login')
  @UseGuards(AuthGuard('google'))
  googleLogin(@Req() req){
    return this.authService.googleLogin(req)
  }

  @Get('google/redirect')
  @UseGuards(AuthGuard('google'))
  googleredirect(){
    return this.authService.googleredirect()
  }


  @Post('signin')
  signin(@Body() loginAuthDto: LoginAuthDto, @Res({passthrough:true}) res) {
    return this.authService.signin(loginAuthDto,res);
  }

  @Get('user')
  GetUser(@Req() req ) {
    return this.authService.GetUser(req);
  }

  @Get('signout')
  signout(@Res() res) {
    return this.authService.signout(res);
  }

  @Post('forgotPassword')
  forgot(@Body() emailDto: EmailAuthDto) {
    return this.authService.forgot(emailDto);
  }

  @Post('resetPassword')
  resetPassword(@Query('token') token: string, @Body() resetPassword: ResetPasswordDto) {
    return this.authService.resetPassword(token, resetPassword);
  }

}