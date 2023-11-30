import { IsNotEmpty ,IsEmail, IsString } from "class-validator";

export class LoginAuthDto {
   @IsNotEmpty()
   @IsEmail()
   public  email:string;
   
    @IsNotEmpty()
    @IsString()
   public  password:string;
}