$(document).ready(function() {

    $('.row').mouseover(function() {
        $(this).css('background-color', 'rgba(191, 0, 0, 0.05');
    });

    $('.row').mouseleave(function() {
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

    $('#source').change(function() {
        var group_uid = $(this).val();
        var route = 'show-group-content';
        $.ajax({
            url: $SCRIPT_ROOT + '/' + route + '/' + group_uid,
            async: false,
            success: function(data) {
                $('#group-detail').html(data);
            }
        });
    });

    $('#service').change(function() {
        var group_uid = $(this).val();
        var route = 'show-app-group-content';
        $.ajax({
            url: $SCRIPT_ROOT + '/' + route + '/' + group_uid,
            async: false,
            success: function(data) {
                $('#app-group-detail').html(data);
            }
        });
    });

});
