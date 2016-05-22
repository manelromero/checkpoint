$(document).ready(function() {

	$('.flash').delay(2000).slideUp(300);
	$('.flash').click(function() {
		$(this).slideUp(300);
	});

	$('.row').mouseover(function() {
		$(this).css('background-color', 'rgba(191, 0, 0, 0.05');
	});

	$('.row').mouseleave(function() {
		$(this).css('background-color', '#fff');
	});

    $('.app-group').click(function() {
        var uid = $(this).data('uid');
    	var route = $(this).data('route');
    	$.ajax({
    		url: $SCRIPT_ROOT + '/' + route + '/' + uid,
    		async: false,
    		success: function(data) {
    			$('[data-group=' + uid + ']').html(data);
    		}
    	});
    	$('[data-group=' + uid + ']').slideToggle(300)

    });

});
