"""Verify all converters are registered and classify by modality."""
from pipeline.converters.factory import _CONVERTER_SPECS
import pyrit.converter as pc

# Modality classification based on class name and constructor params
TEXT_CONVERTERS = {
    "ROT13Converter", "Base64Converter", "LeetspeakConverter", "MorseConverter",
    "BinaryConverter", "BrailleConverter", "NatoConverter", "UrlConverter",
    "FlipConverter", "EmojiConverter", "ZalgoConverter", "ZeroWidthConverter",
    "UnicodeSubstitutionConverter", "CaesarConverter", "AtbashConverter",
    "StringJoinConverter", "SuperscriptConverter", "AsciiArtConverter",
    "AnsiAttackConverter", "ArabiziConverter", "BidiConverter",
    "CodeChameleonConverter", "NegationTrapConverter", "ToneConverter",
    "VariationConverter", "MaliciousQuestionGeneratorConverter",
    "ToxicSentenceGeneratorConverter",
    "AsciiSmugglerConverter", "Base2048Converter", "BinAsciiConverter",
    "CharSwapConverter", "ColloquialWordswapConverter", "EcojiConverter",
    "FirstLetterConverter", "InsertPunctuationConverter",
    "RandomCapitalLettersConverter", "RepeatTokenConverter",
    "SearchReplaceConverter", "SuffixAppendConverter", "TatweelConverter",
    "TemplateSegmentConverter", "UnicodeConfusableConverter",
    "UnicodeReplacementConverter", "VariationSelectorSmugglerConverter",
    "TaskFramingConverter", "SelectiveTextConverter", "PolicyPuppetryConverter",
    "MathObfuscationConverter", "AskToDecodeConverter",
    "SneakyBitsSmugglerConverter", "DenylistConverter",
    "CharacterSpaceConverter", "DiacriticConverter", "NoiseConverter",
    "TranslationConverter", "RandomTranslationConverter", "TenseConverter",
    "PersuasionConverter", "MathPromptConverter", "LLMGenericTextConverter",
    "ScientificTranslationConverter", "ArabicPresentationFormConverter",
    "JsonStringConverter",
}

IMAGE_CONVERTERS = {
    "ImageColorSaturationConverter", "ImageRotationConverter",
    "ImageResizingConverter", "ImageCompressionConverter",
    "ImageOverlayConverter", "ImagePromptStyleConverter",
    "AddTextImageConverter", "AddImageTextConverter",
    "TransparencyAttackConverter", "QRCodeConverter",
}

AUDIO_CONVERTERS = set()  # Azure only, excluded

VIDEO_CONVERTERS = {
    "AddImageVideoConverter",
}

FILE_CONVERTERS = {
    "PDFConverter", "WordDocConverter",
}

registered = 0
failed = []
for cli_name, class_name, needs_target in _CONVERTER_SPECS:
    cls = getattr(pc, class_name, None)
    if cls is None:
        failed.append((cli_name, class_name))
    else:
        registered += 1

print(f"Registered: {registered}/{len(_CONVERTER_SPECS)}")
print(f"Text: {len(TEXT_CONVERTERS)}")
print(f"Image: {len(IMAGE_CONVERTERS)}")
print(f"Audio: {len(AUDIO_CONVERTERS)}")
print(f"Video: {len(VIDEO_CONVERTERS)}")
print(f"File: {len(FILE_CONVERTERS)}")
total_classified = len(TEXT_CONVERTERS) + len(IMAGE_CONVERTERS) + len(AUDIO_CONVERTERS) + len(VIDEO_CONVERTERS) + len(FILE_CONVERTERS)
print(f"Total classified: {total_classified}")
print(f"Failed: {len(failed)}")
for f in failed:
    print(f"  {f}")

# Check which specs are not in any category
all_classified = TEXT_CONVERTERS | IMAGE_CONVERTERS | AUDIO_CONVERTERS | VIDEO_CONVERTERS | FILE_CONVERTERS
unclassified = []
for cli_name, class_name, _ in _CONVERTER_SPECS:
    if class_name not in all_classified:
        unclassified.append((cli_name, class_name))
print(f"\nUnclassified: {len(unclassified)}")
for u in unclassified:
    print(f"  {u}")
