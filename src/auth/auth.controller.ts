import { Controller, Get, Post, Body, Patch, Param, Delete, Query } from '@nestjs/common';
import { AuthService } from './auth.service';
import { CreateAuthDto } from './dto/create-auth.dto';
import { UpdateAuthDto } from './dto/update-auth.dto';

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

}