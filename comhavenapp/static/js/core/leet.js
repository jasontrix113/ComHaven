
$.fn.leet = function (options) {

    this.levels = {
        base: {
            a: "4",
            b: "8",
            c : "(",
            d : "|)",
            e:"3",
            f:"|=",
            g:"6",
            h:"|-|",
            i:"!",
            j:"_|",
            k:"X",
            l:"1",
            m: "44",
            n:"|\|",
            o:"0",
            p:"|*",
            q:"0_",
            r:"|2",
            s:"5",
            t:"7",
            u:"|_|",
            v:"\/",
            w:"\/\/",
            x:"%",
            y:"j",
            z:"2"
        },
        light : {
            a:"@",
            b:"|3",
            c:"(",
            d:"|)",
            e:"£",
            f:"]=",
            g:"9",
            h:"#",
            i:"1",
            j:"_/",
            k:"|<",
            l:"7",
            m:"/\/\\",
            n:"/\/",
            o:"()",
            p:"|o",
            q:"0,",
            r:"2",
            s:"$",
            t:"+",
            u:"(_)",
            v:"√",
            w:"vv",
            x:"><",
            y:"`/",
            z:"≥"
        }
        //a: [
        //    "4",
        //    "@",
        //    "/-\\",
        //    "/\\",
        //    "^",
        //    "∂",
        //    "λ"
        //],
        //b: [
        //    "8",
        //    "|3",
        //    "6",
        //    "13"
        //],
        //c: [
        //    "(",
        //    "<",
        //    "{",
        //    "©"
        //],
        //d: [
        //    "|)",
        //    "[)",
        //    "∂",
        //    "])",
        //    "I>",
        //    "|>"
        //],
        //e: [
        //    "3",
        //    "£",
        //    "&",
        //    "€",
        //    "ə"
        //],
        //f: [
        //    "|=",
        //    "]=",
        //    "}",
        //    "ph",
        //    "(=",
        //    "ʃ"
        //],
        //g: [
        //    "6",
        //    "9",
        //    "&",
        //    "(_+",
        //    "C-",
        //    "(γ,",
        //    "cj"
        //],
        //h: [
        //    "|-|",
        //    "#",
        //    "]-[",
        //    "[-]",
        //    ")-(",
        //    "(-)"
        //],
        //i: [
        //    "!",
        //    "1",
        //    "|",
        //    "¡"
        //],
        //j: [
        //    "_|",
        //    "_/",
        //    "]",
        //    "¿",
        //    "</",
        //    "_)",
        //    "ʝ"
        //],
        //k: [
        //    "X",
        //    "|<",
        //    "|X",
        //    "|{",
        //    "ɮ"
        //],
        //l: [
        //    "1",
        //    "7",
        //    "|_",
        //    "£",
        //    "|",
        //    "|_",
        //    "l",
        //    "¬"
        //],
        //m: [
        //    "44",
        //    "/\/\\",
        //    "|\/|",
        //    "em",
        //    "|v|",
        //    "IYI",
        //    "IVI",
        //    "[V]",
        //    "^^",
        //    "nn",
        //    "//\\//\\",
        //    "(V)",
        //    "(\/)",
        //    "/|\",
        //    "/|/|",
        //    ".\\",
        //    "/^^\\",
        //    "/V\\",
        //    "|^^|",
        //    "AA"
        //],
        //n: [
        //    "|\|",
        //    "/\/",
        //    "//\\//",
        //    "И",
        //    "[\]",
        //    "<\>",
        //    "{\}",
        //    "//",
        //    "₪",
        //    "[]\[]",
        //    "]\["
        //],
        //o: [
        //    "0",
        //    "()",
        //    "[]"
        //],
        //p: [
        //    "|*",
        //    "|o",
        //    "|º",
        //    "|>",
        //    "|"",
        //    "?",
        //    "9",
        //    "[]D",
        //    "|7",
        //    "q",
        //    "þ",
        //    "¶",
        //    "℗",
        //    "|D"
        //],
        //q: [
        //    "0_",
        //    "0,",
        //    "(,)",
        //    "<|",
        //    "9",
        //    "¶"
        //],
        //r: [
        //    "|2",
        //    "2",
        //    "/2",
        //    "I2",
        //    "|^",
        //    "|~",
        //    "lz",
        //    "®",
        //    "|2",
        //    "[z",
        //    "|`",
        //    "l2",
        //    "Я",
        //    ".-",
        //    "ʁ"
        //],
        //s: [
        //    "5",
        //    "$",
        //    "z",
        //    "§"
        //],
        //t: [
        //    "7",
        //    "+",
        //    "-|-",
        //    "1",
        //    "']['",
        //    "†"
        //],
        //u: [
        //    "|_|",
        //    "(_)",
        //    "µ",
        //    "[_]",
        //    "\_/",
        //    "\_\",
        //    "/_/"
        //],
        //v: [
        //    "\/",
        //    "√",
        //    "\\//"
        //],
        //w: [
        //    "\/\/",
        //    "vv",
        //    "'//",
        //    "\\'",
        //    "\^/",
        //    "(n)",
        //    "\X/",
        //    "\|/",
        //    "\_|_/",
        //    "\\//\\//",
        //    "\_:_/",
        //    "]I[",
        //    "UU",
        //    "Ш",
        //    "ɰ",
        //    "￦",
        //    "JL"
        //],
        //x: [
        //    "%",
        //    "><",
        //    "Ж",
        //    "}{",
        //    "ecks",
        //    "×",
        //    "*",
        //    ")(",
        //    "ex"
        //],
        //y: [
        //    "j",
        //    "`/",
        //    "`(",
        //    "-/",
        //    "'/",
        //    "Ψ",
        //    "φ",
        //    "λ",
        //    "Ч",
        //    "¥"
        //],
        //z: [
        //    "2",
        //    "≥",
        //    "~/_",
        //    "%",
        //    "ʒ",
        //    "7_"
        //]
    };


    /**
     * Translate a letter to leet
     *
     * @param letter letter to translate
     * @param level leet level
     *
     * @returns return origin letter if level does not exit even if translated letter
     */
    this.letterToLeet = function (letter, level) {
        var translateLevel  = this.levels[level];
        var translateLetter = translateLevel[letter.toLowerCase()];

        return translateLetter ? translateLetter : letter;
    };

    /**
     * Run translate to leet
     */
    this.translateText = function() {
        if (this.levels[this.level] == undefined) {
            this.errorCallback("Unknown level");
        } else {
            var leetText = '', currentLetter, random, randomBoolean;


            //  To translate options
            //  We can translate all letters or some letters with a random test

            if (this.translateAll) {
                for (var s in this.currentText) {
                    currentLetter = this.currentText[s];
                    random        = Math.floor(Math.random() * 100) + 1;
                    leetText     += this.letterToLeet(currentLetter, this.level);
                }
            } else {
                for (var s in this.currentText) {
                    currentLetter = this.currentText[s];
                    randomBoolean = Math.random() >= 0.5;
                    if (randomBoolean) {
                        leetText += this.letterToLeet(currentLetter, this.level);
                    } else {
                        leetText += currentLetter;
                    }
                }
            }

            this.text (leetText);
        }
    };

    /**
     * reset to original text
     */
    this.reset = function() {
        $(this).text($(this).data('origin'));
    };

    if (typeof options === 'string') {
        this[options]();
    } else {
        $(this).data('origin', this.text().trim());
        this.level         = options.level;
        this.translateAll  = options.translateAll || false;
        this.currentText   = this.text().trim();
        this.errorCallback = options.errorCallback || function(msg) { alert (msg) };

        this.translateText();
    }
};