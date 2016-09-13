$(document).ready(function() {
    // hide animation gif
    $('.loading').hide();
    // wait for 3 seconds and close the modal window if opened
    // setTimeout(function() {
    //     upModal();
    // }, 3000);
    // close the modal window on window click
    $('.wrapper-modal').click(function() {
        upModal();
    });
    // close the modal window on 'x' click
    $('.close-window').click(function() {
        upModal();
    });
    //
    $('.waiting').click(function() {
        setTimeout(function() {
            $('.loading').show();
        }, 400);
    });
    //
    $('.row').mouseover(function() {
        $(this).css('background-color', 'rgba(191, 0, 0, 0.05');
    });
    //
    $('.row').mouseleave(function() {
        $(this).css('background-color', '#fff');
    });
    //
    $('.members').on('mouseover', '.member', function() {
        $(this).css('background-color', 'rgba(191, 0, 0, 0.05');
    });
    //
    $('.members').on('mouseleave', '.member', function() {
        $(this).css('background-color', '#f5f5f5');
    });
    // close modal window
    function upModal() {
        $('.wrapper-modal').slideUp(200);
        $('.wrapper-modal').css('background-color', 'rgba(255, 255, 255, 0');
    }
    // set cookie
    function setCookie(cname, cvalue, exdays) {
        var d = new Date();
        d.setTime(d.getTime() + (exdays*24*60*60*1000));
        var expires = "expires="+ d.toUTCString();
        document.cookie = cname + "=" + cvalue + "; " + expires;
    }
    // get cookie
    function getCookie(cname) {
        var name = cname + '=';
        var ca = document.cookie.split(';');
        for (var i = 0; i < ca.length; i++) {
            var c = ca[i];
            while (c.charAt(0) == ' ') {
                c = c.substring(1);
            }
            if (c.indexOf(name) === 0) {
                return c.substring(name.length, c.length);
            }
        }
    return '';
    }
    // make ajax calls
    function ajaxCall(url) {
        return $.ajax({
            url: url
        });
    }
    // open drop menu
    function openMenu(row) {
        var group_name = row.data('group-name'),
            route = row.data('route'),
            url_back = row.data('url-back'),
            child = row.children('.arrow');
        // show animation gif
        $('.loading').show();
        // build the route
        var url = $SCRIPT_ROOT + '/' + route + '/' + group_name + '/' + url_back;
        // ajax call
        $.when(ajaxCall(url)).done(function(data) {
            $('#' + group_name).html(data);
            row.removeClass('closed');
            row.addClass('open');
            child.removeClass('right');
            child.addClass('down');
            $('#' + group_name).slideDown(150);
            // hide animation gif
            $('.loading').hide();
        });
    }
    // close drop menu
    function closeMenu(row) {
        var group_name = row.data('group-name'),
            child = row.children('.arrow');
        row.removeClass('open');
        row.addClass('closed');
        child.removeClass('down');
        child.addClass('right');
        $('#' + group_name).slideUp(150);
    }
    // open group if cookie stored
    $('.group').each(function() {
        var cookie = getCookie($(this).data('group-name'));
        if (cookie == 'open') {
            openMenu($(this));
        }
    });
    // listen for click to open a drop menu
    $('.table').on('click', '.closed', function() {
        openMenu($(this));
        setCookie($(this).data('group-name'), 'open');
    });
    // listen for click to close a drop menu
    $('.table').on('click', '.open', function() {
        closeMenu($(this));
        setCookie($(this).data('group-name'), 'closed', -1);
    });
});
