$(document).ready(function() {

	$('.row').mouseover(function() {
		$(this).css('background-color', 'rgba(191, 0, 0, 0.05');
	});

	$('.row').mouseleave(function() {
		$(this).css('background-color', '#fff');
	});

	$('.flash').click(function() {
		$(this).hide();
	});

});
