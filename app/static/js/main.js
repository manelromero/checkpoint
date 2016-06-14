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
    });

    $('.members').on('mouseleave', '.member', function() {
        $(this).css('background-color', '#f5f5f5');
    });


    function setCookie(cname, cvalue, exdays) {
        var d = new Date();
        d.setTime(d.getTime() + (exdays*24*60*60*1000));
        var expires = "expires="+ d.toUTCString();
        document.cookie = cname + "=" + cvalue + "; " + expires;
    }
    
    function getCookie(cname) {
        var name = cname + '=';
        var ca = document.cookie.split(';');
        for (var i = 0; i < ca.length; i++) {
            var c = ca[i];
            while (c.charAt(0) == ' ') {
                c = c.substring(1);
            }
            if (c.indexOf(name) == 0) {
                return c.substring(name.length, c.length);
            }
        }
    return '';
    };

    function openMenu(row) {
        var group_name = row.data('group-name'),
            route = row.data('route'),
            url_back = row.data('url-back'),
            child = row.children('.arrow')

        $.ajax({
            url: $SCRIPT_ROOT + '/' + route + '/' + group_name + '/' + url_back,
            async: false,
            success: function(data) {
                $('#' + group_name).html(data);
            }
        });

        row.removeClass('closed');
        row.addClass('open');
        child.removeClass('right');
        child.addClass('down');
        $('#' + group_name).slideDown(200);
    }

    function closeMenu(row) {
        var group_name = row.data('group-name'),
            child = row.children('.arrow')

        row.removeClass('open');
        row.addClass('closed');
        child.removeClass('down');
        child.addClass('right');
        $('#' + group_name).slideUp(200);
    }

    $('.group').each(function() {
        var cookie = getCookie($(this).data('group-name'));
        if (cookie == 'open') {
            openMenu($(this));
        }
    });

    $('.table').on('click', '.closed', function() {
        openMenu($(this));
        setCookie($(this).data('group-name'), 'open');
    });

    $('.table').on('click', '.open', function() {
        closeMenu($(this));
        setCookie($(this).data('group-name'), 'closed', -1);
    });

});
