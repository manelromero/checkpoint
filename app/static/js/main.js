$(document).ready(function() {

    $('.row').mouseover(function() {
        $(this).css('background-color', 'rgba(191, 0, 0, 0.05');
    });

    $('.row').mouseleave(function() {
        $(this).css('background-color', '#fff');
    });

    $('.member').mouseover(function() {
        $(this).css('background-color', 'rgba(191, 0, 0, 1');
    });

    $('.member').mouseleave(function() {
        $(this).css('background-color', '#fff');
    });

    $('.unfold').click(function() {
        var uid = $(this).data('uid');
    	var route = $(this).data('route');
    	$.ajax({
    		url: $SCRIPT_ROOT + '/' + route + '/' + uid,
    		async: false,
    		success: function(data) {
    			$('[data-group=' + uid + ']').html(data);
    		}
    	});
        $(this).toggleClass('more');
    	$('[data-group=' + uid + ']').slideToggle(300)
    });

    $('#smart').click(function() {
        data = {username:'admin', userPass:'developer1'}
        $.ajax({
            type: 'POST',
            url: 'https://192.168.1.10/cgi-bin/home.tcl',
            data: data,
            success: function(data) {
                $('#result').html(data);
            }
        });


    })

});
