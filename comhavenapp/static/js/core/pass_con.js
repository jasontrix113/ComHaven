var allowsubmit = false;
		$(function(){
			//on keypress 
			$('#id_password2').keyup(function(e){
				//get values 
				var pass = $('#id_password1').val();
				var confpass = $(this).val();
				
				//check the strings
				if(pass == confpass){
					//if both are same remove the error and allow to submit
					$('.error').text('');
					allowsubmit = true;
				}else{
					//if not matching show error and not allow to submit
					$('.error').text('Password do not match');
					allowsubmit = false;
				}
			});
			
			//jquery form submit
			$('#form').submit(function(){
			
				var pass = $('#id_password1').val();
				var confpass = $('#id_password2').val();
 
				//just to make sure once again during submit
				//if both are true then only allow submit
				if(pass == confpass){
					allowsubmit = true;
				}
				if(allowsubmit){
					return true;
				}else{
					return false;
				}
			});
		});
