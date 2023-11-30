import { IsNotEmpty, IsEmail, IsString } from 'class-validator';

export class CreateAuthGoogleDto {
    @IsNotEmpty()
    public id: string; 

  @IsNotEmpty()
  @IsEmail()
  public email: string;

  @IsNotEmpty()
  @IsString()
  public name: string;


}
