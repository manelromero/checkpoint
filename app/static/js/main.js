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

    $('.table').on('click', '.closed', function() {
        var group_name = $(this).data('group-name');
        var route = $(this).data('route');
    	var url_back = $(this).data('url-back');
    	$.ajax({
    		url: $SCRIPT_ROOT + '/' + route + '/' + group_name + '/' + url_back,
    		async: false,
    		success: function(data) {
    			$('#' + group_name).html(data);
    		}
    	});
        $(this).removeClass('closed');
        $(this).children('.arrow').removeClass('closed');
        $(this).addClass('open');
        $(this).children('.arrow').addClass('open');
    	$('#' + group_name).slideDown(200)
    });

    $('.table').on('click', '.open', function() {
        var group_name = $(this).data('group-name');
        $(this).removeClass('open');
        $(this).children('.arrow').removeClass('open');
        $(this).addClass('closed');
        $(this).children('.arrow').addClass('closed');
        $('#' + group_name).slideUp(200)
    })

});
