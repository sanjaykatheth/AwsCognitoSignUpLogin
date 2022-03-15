package com.awscognito.model;

	public class ConfirmPassword {
		private String email;
		private String confirmCode;
        private String newpassword;
		public String getEmail() {
			return email;
		}
		public void setEmail(String email) {
			this.email = email;
		}
		public String getConfirmCode() {
			return confirmCode;
		}
		public void setConfirmCode(String confirmCode) {
			this.confirmCode = confirmCode;
		}
		public String getNewpassword() {
			return newpassword;
		}
		public void setNewpassword(String newpassword) {
			this.newpassword = newpassword;
		}
        

}
