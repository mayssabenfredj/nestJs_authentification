import { Controller, Get, Post, Body, Patch, Param, Delete, Query, UseGuards, Req } from '@nestjs/common';
import { AuthService } from './auth.service';
import { CreateAuthDto } from './dto/create-auth.dto';
import { AuthGuard } from '@nestjs/passport'


import { UpdateAuthDto } from './dto/update-auth.dto';
import { EmailAuthDto } from './dto/email-auth.dto';

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
}