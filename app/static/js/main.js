$(document).ready(function() {

    $('.flash').delay(3000).animate({left: '-200'});

    $('.row').mouseover(function() {
        $(this).css('background-color', 'rgba(191, 0, 0, 0.05');
    });

    $('.row').mouseleave(function() {
        $(this).css('background-color', '#fff');
    });

    $('.members').on('mouseover', '.member', function() {
        $(this).css('background-color', 'rgba(191, 0, 0, 0.05');
    })

    $('.members').on('mouseleave', '.member', function() {
        $(this).css('background-color', '#f5f5f5');
    })

    $('.unfold').click(function() {
        var uid = $(this).data('uid');
        var route = $(this).data('route');
    	var url_back = $(this).data('url-back');
    	$.ajax({
    		url: $SCRIPT_ROOT + '/' + route + '/' + uid + '/' + url_back,
    		async: false,
    		success: function(data) {
    			$('[data-group=' + uid + ']').html(data);
    		}
    	});
        $(this).toggleClass('more');
    	$('[data-group=' + uid + ']').slideToggle(300)
    });

});
