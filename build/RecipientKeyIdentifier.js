"use strict";

Object.defineProperty(exports, "__esModule", {
	value: true
});

var _createClass = function () { function defineProperties(target, props) { for (var i = 0; i < props.length; i++) { var descriptor = props[i]; descriptor.enumerable = descriptor.enumerable || false; descriptor.configurable = true; if ("value" in descriptor) descriptor.writable = true; Object.defineProperty(target, descriptor.key, descriptor); } } return function (Constructor, protoProps, staticProps) { if (protoProps) defineProperties(Constructor.prototype, protoProps); if (staticProps) defineProperties(Constructor, staticProps); return Constructor; }; }();

var _asn1js = require("asn1js");

var asn1js = _interopRequireWildcard(_asn1js);

var _pvutils = require("pvutils");

var _OtherKeyAttribute = require("./OtherKeyAttribute");

var _OtherKeyAttribute2 = _interopRequireDefault(_OtherKeyAttribute);

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

function _interopRequireWildcard(obj) { if (obj && obj.__esModule) { return obj; } else { var newObj = {}; if (obj != null) { for (var key in obj) { if (Object.prototype.hasOwnProperty.call(obj, key)) newObj[key] = obj[key]; } } newObj.default = obj; return newObj; } }

function _classCallCheck(instance, Constructor) { if (!(instance instanceof Constructor)) { throw new TypeError("Cannot call a class as a function"); } }

//**************************************************************************************

var RecipientKeyIdentifier = function () {
	//**********************************************************************************
	/**
  * Constructor for RecipientKeyIdentifier class
  * @param {Object} [parameters={}]
  * @property {Object} [schema] asn1js parsed value
  */

	function RecipientKeyIdentifier() {
		var parameters = arguments.length <= 0 || arguments[0] === undefined ? {} : arguments[0];

		_classCallCheck(this, RecipientKeyIdentifier);

		//region Internal properties of the object
		/**
   * @type {OctetString}
   * @description subjectKeyIdentifier
   */
		this.subjectKeyIdentifier = (0, _pvutils.getParametersValue)(parameters, "subjectKeyIdentifier", RecipientKeyIdentifier.defaultValues("subjectKeyIdentifier"));

		if ("date" in parameters)
			/**
    * @type {GeneralizedTime}
    * @description date
    */
			this.date = (0, _pvutils.getParametersValue)(parameters, "date", RecipientKeyIdentifier.defaultValues("date"));

		if ("other" in parameters)
			/**
    * @type {OtherKeyAttribute}
    * @description other
    */
			this.other = (0, _pvutils.getParametersValue)(parameters, "other", RecipientKeyIdentifier.defaultValues("other"));
		//endregion

		//region If input argument array contains "schema" for this object
		if ("schema" in parameters) this.fromSchema(parameters.schema);
		//endregion
	}
	//**********************************************************************************
	/**
  * Return default values for all class members
  * @param {string} memberName String name for a class member
  */


	_createClass(RecipientKeyIdentifier, [{
		key: "fromSchema",

		//**********************************************************************************
		/**
   * Convert parsed asn1js object into current class
   * @param {!Object} schema
   */
		value: function fromSchema(schema) {
			//region Check the schema is valid
			var asn1 = asn1js.compareSchema(schema, schema, RecipientKeyIdentifier.schema({
				names: {
					subjectKeyIdentifier: "subjectKeyIdentifier",
					date: "date",
					other: {
						names: {
							blockName: "other"
						}
					}
				}
			}));

			if (asn1.verified === false) throw new Error("Object's schema was not verified against input data for RecipientKeyIdentifier");
			//endregion

			//region Get internal properties from parsed schema
			this.subjectKeyIdentifier = asn1.result.subjectKeyIdentifier;

			if ("date" in asn1.result) this.date = asn1.result.date;

			if ("other" in asn1.result) this.other = new _OtherKeyAttribute2.default({ schema: asn1.result.other });
			//endregion
		}
		//**********************************************************************************
		/**
   * Convert current object to asn1js object and set correct values
   * @returns {Object} asn1js object
   */

	}, {
		key: "toSchema",
		value: function toSchema() {
			//region Create array for output sequence
			var outputArray = [];

			outputArray.push(this.subjectKeyIdentifier);

			if ("date" in this) outputArray.push(this.date);

			if ("other" in this) outputArray.push(this.other.toSchema());
			//endregion

			//region Construct and return new ASN.1 schema for this object
			return new asn1js.Sequence({
				value: outputArray
			});
			//endregion
		}
		//**********************************************************************************
		/**
   * Convertion for the class to JSON object
   * @returns {Object}
   */

	}, {
		key: "toJSON",
		value: function toJSON() {
			var _object = {
				subjectKeyIdentifier: this.subjectKeyIdentifier.toJSON()
			};

			if ("date" in this) _object.date = this.date;

			if ("other" in this) _object.other = this.other.toJSON();

			return _object;
		}
		//**********************************************************************************

	}], [{
		key: "defaultValues",
		value: function defaultValues(memberName) {
			switch (memberName) {
				case "subjectKeyIdentifier":
					return new asn1js.OctetString();
				case "date":
					return new asn1js.GeneralizedTime();
				case "other":
					return new _OtherKeyAttribute2.default();
				default:
					throw new Error("Invalid member name for RecipientKeyIdentifier class: " + memberName);
			}
		}
		//**********************************************************************************
		/**
   * Compare values with default values for all class members
   * @param {string} memberName String name for a class member
   * @param {*} memberValue Value to compare with default value
   */

	}, {
		key: "compareWithDefault",
		value: function compareWithDefault(memberName, memberValue) {
			switch (memberName) {
				case "subjectKeyIdentifier":
					return memberValue.isEqual(RecipientKeyIdentifier.defaultValues("subjectKeyIdentifier"));
				case "date":
					return memberValue.year === 0 && memberValue.month === 0 && memberValue.day === 0 && memberValue.hour === 0 && memberValue.minute === 0 && memberValue.second === 0 && memberValue.millisecond === 0;
				case "other":
					return memberValue.keyAttrId === "" && "keyAttr" in memberValue === false;
				default:
					throw new Error("Invalid member name for RecipientKeyIdentifier class: " + memberName);
			}
		}
		//**********************************************************************************
		/**
   * Return value of asn1js schema for current class
   * @param {Object} parameters Input parameters for the schema
   * @returns {Object} asn1js schema object
   */

	}, {
		key: "schema",
		value: function schema() {
			var parameters = arguments.length <= 0 || arguments[0] === undefined ? {} : arguments[0];

			//RecipientKeyIdentifier ::= SEQUENCE {
			//    subjectKeyIdentifier SubjectKeyIdentifier,
			//    date GeneralizedTime OPTIONAL,
			//    other OtherKeyAttribute OPTIONAL }

			/**
    * @type {Object}
    * @property {string} [blockName]
    * @property {string} [type]
    * @property {string} [setName]
    * @property {string} [values]
    */
			var names = (0, _pvutils.getParametersValue)(parameters, "names", {});

			return new asn1js.Sequence({
				name: names.blockName || "",
				value: [new asn1js.OctetString({ name: names.subjectKeyIdentifier || "" }), new asn1js.GeneralizedTime({
					optional: true,
					name: names.date || ""
				}), _OtherKeyAttribute2.default.schema(names.other || {})]
			});
		}
	}]);

	return RecipientKeyIdentifier;
}();
//**************************************************************************************


exports.default = RecipientKeyIdentifier;
//# sourceMappingURL=RecipientKeyIdentifier.js.map